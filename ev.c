/* SPDX-License-Identifier: The Unlicense */

#include "ev.h"

#include <sys/epoll.h>
#include <sys/timerfd.h>


#ifndef rdtscll
#define rdtscll(val) \
	__asm__ __volatile__("rdtsc" : "=A" (val))
#endif

#undef __always_inline
#if __GNUC_PREREQ (3,2)
# define __always_inline __inline __attribute__ ((__always_inline__))
#else
# define __always_inline __inline
#endif

#if !defined(likely) && !defined(unlikely)
# define likely(x)   __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#if !defined(ARRAY_SIZE)
# define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#if defined(LIBEVE_DEBUG)
#define pr_debug(fmt_str, ...) \
	fprintf(stderr, fmt_str, ##__VA_ARGS__)
#define	eve_assert(x) assert(x)
#else
#define pr_debug(fmt_str, ...) \
        ({ if (0) fprintf(stderr, fmt_str, ##__VA_ARGS__); 0; })
#define	eve_assert(x)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>

/* FIXME: check for wrong subtraction/addition operation of struct timespec */

/* cmp: <, <=, >, >= or == */
#define timespec_cmp(tvp, uvp, cmp)               \
	(((tvp)->tv_sec == (uvp)->tv_sec) ?       \
	 ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :    \
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define	timespec_eq(tvp, uvp) \
	(((tvp)->tv_sec == (uvp)->tv_sec) && ((tvp)->tv_nsec == (uvp)->tv_nsec))

#define timespec_add(res, vvp, uvp)                       \
do {                                                      \
	(res)->tv_sec  = (vvp)->tv_sec  + (uvp)->tv_sec;  \
	(res)->tv_nsec = (vvp)->tv_nsec + (uvp)->tv_nsec; \
	if ((res)->tv_nsec >= 1000000000) {               \
		(res)->tv_sec++;                          \
		(res)->tv_nsec -= 1000000000;             \
	}                                                 \
} while (0)

#define timespec_sub(res, vvp, uvp)                       \
do {                                                      \
	(res)->tv_sec = (vvp)->tv_sec - (uvp)->tv_sec;    \
	(res)->tv_nsec = (vvp)->tv_nsec - (uvp)->tv_nsec; \
	if ((res)->tv_nsec < 0) {                         \
		(res)->tv_sec--;                          \
		(res)->tv_nsec += 1000000000;             \
	}                                                 \
} while (0)

struct ev {
	int fd;
	int break_loop;
	unsigned int size;

	/* implementation specific data, e.g. select timer handling
	 * will use this to store the rbtree */
	void *priv_data;
};

struct ev_entry {

	/* monitored FD if type is EV_READ or EV_WRITE */
	int fd;

	/* EV_READ, EV_WRITE or EV_TIMEOUT */
	int type;

	/* timeout val if type is EV_TIMEOUT */
	struct timespec timespec;

	union {
		void (*fd_cb)(int, int, void *);
		void (*timer_cb)(void *);
	};

	/* user provided pointer to data */
	void *data;

	/* implementation specific data (e.g. for epoll, select) */
	void *priv_data;
};

unsigned int ev_size(struct ev *e) {
	return e->size;
}

int ev_fd(struct ev *e) {
	return e->fd;
}


static struct ev *struct_ev_new_internal(void)
{
	struct ev *ev;

	ev = malloc(sizeof(*ev));
	if (!ev)
		return NULL;

	memset(ev, 0, sizeof(*ev));

	return ev;
}

inline void ev_entry_set_data(struct ev_entry *entry, void *data)
{
	entry->data = data;
}

int ev_run_out(struct ev *ev)
{
	eve_assert(ev);
	ev->break_loop = 1;
	return 0;
}

/* similar for all implementations, at least
 * under Linux. Solaris, AIX, etc. differs and need
 * a separate implementation */
int ev_set_non_blocking(int fd) {
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -EINVAL;

	flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (flags < 0)
		return -EINVAL;

	return 0;
}


struct ev_entry_data_epoll {
	uint32_t flags;
};

#define EVE_EPOLL_ARRAY_SIZE 64

void ev_destroy(struct ev *ev)
{
	eve_assert(ev);
	eve_assert(ev->fd != -1);

	/* close epoll descriptor */
	close(ev->fd);

	/* clear potential secure data */
	memset(ev, 0, sizeof(struct ev));
	free(ev);
}

static inline int ev_new_flags_convert(int flags)
{
	if (flags == 0)
		return 0;

	if (flags == EV_CLOEXEC)
		return EPOLL_CLOEXEC;

	return -EINVAL;
}

struct ev *ev_new(int flags)
{
	struct ev *ev;
	int flags_epoll;

	flags_epoll = ev_new_flags_convert(flags);
	if (flags_epoll < 0) {
		return NULL;
	}

	ev = struct_ev_new_internal();
	if (!ev)
		return NULL;

	ev->fd = epoll_create1(flags_epoll);
	if (ev->fd < 0) {
		free(ev);
		return NULL;
	}

	ev->size = 0;
	ev->break_loop = 0;

	return ev;
}

struct ev_entry *ev_entry_new_epoll_internal(void)
{
	struct ev_entry *ev_entry;

	ev_entry = malloc(sizeof(struct ev_entry));
	if (!ev_entry)
		return NULL;

	memset(ev_entry, 0, sizeof(struct ev_entry));

	ev_entry->priv_data = malloc(sizeof(struct ev_entry_data_epoll));
	if (!ev_entry->priv_data) {
		free(ev_entry);
		return NULL;
	}

	memset(ev_entry->priv_data, 0, sizeof(struct ev_entry_data_epoll));

	return ev_entry;
}

struct ev_entry *ev_entry_new(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	struct ev_entry *ev_entry;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	eve_assert(what == EV_READ || what == EV_WRITE);
	eve_assert(cb);
	eve_assert(fd >= 0);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->fd    = fd;
	ev_entry->type  = what;
	ev_entry->fd_cb = cb;
	ev_entry->data  = data;

	ev_entry_data_epoll = ev_entry->priv_data;

	switch (what) {
	case EV_READ:
		ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
		break;
	case EV_WRITE:
		ev_entry_data_epoll->flags = EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP;
		break;
	default:
		/* cannot happen - previously catched via assert(3) */
		break;
	}

	return ev_entry;
}

struct ev_entry *ev_timer_new(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	struct ev_entry *ev_entry;

	eve_assert(timespec && cb);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->type     = EV_TIMEOUT;
	ev_entry->timer_cb = cb;
	ev_entry->data     = data;

	memcpy(&ev_entry->timespec, timespec, sizeof(struct timespec));

	return ev_entry;
}

void ev_entry_free(struct ev_entry *ev_entry)
{
	eve_assert(ev_entry);
	eve_assert(ev_entry->priv_data);

	free(ev_entry->priv_data);
	memset(ev_entry, 0, sizeof(struct ev_entry));
	free(ev_entry);
}

static int ev_arm_timerfd_internal(struct ev_entry *ev_entry)
{
	int ret, fd;
	struct timespec now;
	struct itimerspec new_value;
	struct ev_entry_data_epoll *ev_entry_data_epoll = ev_entry->priv_data;

	memset(&new_value, 0, sizeof(struct itimerspec));

	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (ret < 0) {
		return -EINVAL;
	}

	new_value.it_value.tv_sec  = now.tv_sec  + ev_entry->timespec.tv_sec;
	new_value.it_value.tv_nsec = now.tv_nsec + ev_entry->timespec.tv_nsec;

	/* timerfd_settime() cannot handle larger nsecs - catch overflow */
	if (new_value.it_value.tv_nsec >= 1000000000) {
		new_value.it_value.tv_sec++;
		new_value.it_value.tv_nsec -= 1000000000;
		eve_assert(new_value.it_value.tv_nsec > 0);
	}

	new_value.it_interval.tv_sec  = 0;
	new_value.it_interval.tv_nsec = 0;

	fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd < 0) {
		return -EINVAL;
	}

	ret = timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL);
	if (ret < 0) {
		close(fd);
		return -EINVAL;
	}

	ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;

	ev_entry->fd = fd;

	return 0;
}

int ev_add(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	eve_assert(ev);
	eve_assert(ev_entry);

	ev_entry_data_epoll = ev_entry->priv_data;

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	if ((ev_entry->type == EV_TIMEOUT) &&
			(ev_arm_timerfd_internal(ev_entry) != 0)) {
		return -EINVAL;
	}

	/* FIXME: the mapping must be a one to one mapping */
	epoll_ev.events   = ev_entry_data_epoll->flags;
	epoll_ev.data.ptr = ev_entry;

	ret = epoll_ctl(ev->fd, EPOLL_CTL_ADD, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		return -EINVAL;
	}

	ev->size++;

	return 0;
}

int ev_del(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;

	eve_assert(ev);
	eve_assert(ev_entry);

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	ret = epoll_ctl(ev->fd, EPOLL_CTL_DEL, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		return -EINVAL;
	}

	ev->size--;

	return 0;
}

int ev_timer_cancel(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;

	eve_assert(ev_entry);
	eve_assert(ev_entry->type == EV_TIMEOUT);

	ret = ev_del(ev, ev_entry);
	if (ret != 0)
		return -EINVAL;

	/* close the timer fd specific descriptor */
	close(ev_entry->fd);
	ev_entry_free(ev_entry);

	return 0;
}

static inline void ev_process_call_epoll_timeout(
		struct ev *ev, struct ev_entry *ev_entry)
{
	ssize_t ret;
	int64_t time_buf;

	/* first of all - call user callback */
	ev_entry->timer_cb(ev_entry->data);

	/* and now: cleanup timer specific data and
	 * finally all event specific data */
	ret = read(ev_entry->fd, &time_buf, sizeof(int64_t));
	if ((ret < (ssize_t)sizeof(int64_t)) ||
			(time_buf > 1)) {
		/* failure - should not happens: kernel bug */
		eve_assert(0);
	}

	ev_del(ev, ev_entry);
	close(ev_entry->fd);
	ev_entry_free(ev_entry);
}


static inline void ev_process_call_internal(
		struct ev *ev, struct ev_entry *ev_entry)
{
	(void) ev;

	eve_assert(ev_entry);

	switch (ev_entry->type) {
	case EV_READ:
	case EV_WRITE:
		ev_entry->fd_cb(ev_entry->fd, ev_entry->type, ev_entry->data);
		return;
		break;
	case EV_TIMEOUT:
		ev_process_call_epoll_timeout(ev, ev_entry);
		break;
	default:
		return;
		break;
	}
	return;
}

int ev_loop(struct ev *ev, uint32_t flags)
{
	int nfds, i;
	struct epoll_event events[EVE_EPOLL_ARRAY_SIZE];

	eve_assert(ev);

	(void) flags; /* currently ignored */

	while (ev->size > 0) {
		nfds = epoll_wait(ev->fd, events, EVE_EPOLL_ARRAY_SIZE, -1);
		if (nfds < 0) {
			return -EINVAL;
		}

		/* multiplex and call the registerd callback handler */
		for (i = 0; i < nfds; i++) {
			struct ev_entry *ev_entry = (struct ev_entry *)events[i].data.ptr;
			ev_process_call_internal(ev, ev_entry);
		}

		if (ev->break_loop)
			break;
	}

	return 0;
}

