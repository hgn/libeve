/* SPDX-License-Identifier: The Unlicense */

#include "ev.h"

#define __STDC_LIMIT_MACROS

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>

#if defined(SDT_ENABLED)
/*
 * Quote sdt-config.h.in: Defines
 * '_SDT_ASM_SECTION_AUTOGROUP_SUPPORT to 0 or 1
 * to indicate whether the assembler supports "?"
 * in .pushsection directives.'
 * We define this to 0 - we don't assume that all
 * possible compilers on all possible archs support
 * this feature. BUT: if you realize C++ link errors
 * you may want to enable this flag.
 */
# define _SDT_ASM_SECTION_AUTOGROUP_SUPPORT 0
# include <sdt-owned.h>
#else
# define STAP_PROBE(a, b)
# define STAP_PROBE1(a, b, c)
# define STAP_PROBE2(a, b, c, d)
#endif

#ifndef rdtscll
# define rdtscll(val) \
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
# define pr_debug(fmt_str, ...) \
	fprintf(stderr, fmt_str, ##__VA_ARGS__)
# define	eve_assert(x) assert(x)
#else
# define pr_debug(fmt_str, ...) \
        ({ if (0) fprintf(stderr, fmt_str, ##__VA_ARGS__); 0; })
# define	eve_assert(x)
#endif

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


#define EVE_EPOLL_ARRAY_SIZE 64


struct ev {
	int fd;
	int break_loop;
	unsigned long long entries;

	/* implementation specific data, e.g. select timer handling
	 * will use this to store the rbtree */
	void *priv_data;
};


struct ev_entry {
	/* monitored FD if type is EV_READ or EV_WRITE */
	int fd;

	/* EV_* if raw is 0 -> type is used. E.g for
	 * EV_READ, EV_WRITE or EV_TIMEOUT_ONESHOT.\
	 * EV_RAW_* if raw is 1 -> type_raw is used then
	 */
	union {
		int type;
		uint32_t type_raw;
	};

	/* 0 for "old" mode, if 1 type is interpreted identical
	 * as epoll_ctl flags */
	int raw;

	/* timeout val if type is EV_TIMEOUT_ONESHOT */
	struct timespec timespec;

	union {
		void (*fd_cb)(int, int, void *);
		void (*fd_cb_raw)(int, uint32_t, void *);
		void (*timer_cb_oneshot)(void *);
		void (*timer_cb_periodic)(unsigned long long, void *);
		void (*signal_cb)(uint32_t, uint32_t, void *);
	};

	/* user provided pointer to data */
	void *data;

	/* implementation specific data (e.g. for epoll, select) */
	void *priv_data;
};


unsigned long long ev_entries(struct ev *e) {
	return e->entries;
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


void ev_entry_set_data(struct ev_entry *entry,
			      void *data)
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
	/* std fd handling data */
	uint32_t flags;
	union {
		sigset_t signal_mask;
	};
};


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

	ev->entries = 0;
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
	ev_entry->raw   = 0;

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

struct ev_entry *ev_entry_new_raw(int fd, uint32_t events,
		void (*cb)(int, uint32_t, void *), void *data)
{
	struct ev_entry *ev_entry;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	eve_assert(cb);
	eve_assert(fd >= 0);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->fd = fd;
	ev_entry->type_raw = events;
	ev_entry->fd_cb_raw = cb;
	ev_entry->raw = 1;
	ev_entry->data = data;

	ev_entry_data_epoll = ev_entry->priv_data;
	ev_entry_data_epoll->flags = events;

	return ev_entry;
}


struct ev_entry *ev_timer_oneshot_new(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	struct ev_entry *ev_entry;

	eve_assert(timespec && cb);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->type = EV_TIMEOUT_ONESHOT;
	ev_entry->data = data;
	ev_entry->timer_cb_oneshot = cb;
	ev_entry->raw = 0;

	memcpy(&ev_entry->timespec, timespec, sizeof(struct timespec));

	return ev_entry;
}


struct ev_entry *ev_timer_periodic_new(struct timespec *timespec,
		void (*cb)(unsigned long long, void *), void *data)
{
	struct ev_entry *ev_entry;

	eve_assert(timespec && cb);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->type = EV_TIMEOUT_PERIODIC;
	ev_entry->data = data;
	ev_entry->timer_cb_periodic = cb;
	ev_entry->raw = 0;

	memcpy(&ev_entry->timespec, timespec, sizeof(struct timespec));

	return ev_entry;
}


static void ev_entry_timer_free(struct ev_entry *ev_entry)
{
	eve_assert(ev_entry);

	close(ev_entry->fd);
}


static void ev_entry_signal_free(struct ev_entry *ev_entry)
{
	eve_assert(ev_entry);

	close(ev_entry->fd);
}


void ev_entry_free(struct ev_entry *ev_entry)
{
	eve_assert(ev_entry);
	eve_assert(ev_entry->priv_data);

	if (ev_entry->raw)
		goto out;

	switch (ev_entry->type) {
	case EV_TIMEOUT_ONESHOT:
	case EV_TIMEOUT_PERIODIC:
		ev_entry_timer_free(ev_entry);
		break;
	case EV_SIGNAL:
		ev_entry_signal_free(ev_entry);
		break;
	default:
		// other events have no special cleaning
		// functions. do nothing
		break;
	}

out:
	free(ev_entry->priv_data);
	memset(ev_entry, 0, sizeof(struct ev_entry));
	free(ev_entry);
}


static int ev_arm_timerfd_oneshot(struct ev_entry *ev_entry)
{
	int ret, fd;
	struct timespec now;
	struct itimerspec new_value;
	struct ev_entry_data_epoll *ev_entry_data_epoll = ev_entry->priv_data;

	memset(&new_value, 0, sizeof(struct itimerspec));

	ret = clock_gettime(CLOCK_MONOTONIC, &now);
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

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		return -EINVAL;
	}

	ret = timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL);
	if (ret < 0) {
		close(fd);
		return -EINVAL;
	}

	ret = ev_set_non_blocking(fd);
	if (ret < 0) {
		close(fd);
		return -EINVAL;
	}

	ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;

	ev_entry->fd = fd;

	return 0;
}


static int ev_arm_timerfd_periodic(struct ev_entry *ev_entry)
{
	int ret, fd;
	struct itimerspec new_value;
	struct ev_entry_data_epoll *ev_entry_data_epoll = ev_entry->priv_data;

	new_value.it_value.tv_sec  = ev_entry->timespec.tv_sec;
	new_value.it_value.tv_nsec = ev_entry->timespec.tv_nsec;

	new_value.it_interval.tv_sec  = ev_entry->timespec.tv_sec;
	new_value.it_interval.tv_nsec = ev_entry->timespec.tv_nsec;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		return -EINVAL;
	}

	ret = timerfd_settime(fd, 0, &new_value, NULL);
	if (ret < 0) {
		close(fd);
		return -EINVAL;
	}

	ret = ev_set_non_blocking(fd);
	if (ret < 0) {
		close(fd);
		return -EINVAL;
	}

	ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;

	ev_entry->fd = fd;

	return 0;
}


int ev_signal_catch(struct ev_entry *ev_entry, int signal_no)
{
	struct ev_entry_data_epoll *ev_entry_data_epoll = ev_entry->priv_data;

	sigaddset(&ev_entry_data_epoll->signal_mask, signal_no);

	return 0;
}


static int ev_arm_signal(struct ev_entry *ev_entry)
{
	int ret, fd;
	struct ev_entry_data_epoll *ev_entry_data_epoll = ev_entry->priv_data;

	ret = sigprocmask(SIG_BLOCK, &ev_entry_data_epoll->signal_mask, NULL);
	if (ret < 0) {
		pr_debug("sigprocmask");
		return -EINVAL;
	}

	fd = signalfd(-1, &ev_entry_data_epoll->signal_mask, 0);
	if (fd < 0) {
		pr_debug("signalfd");
		return -EINVAL;
	}

	ret = ev_set_non_blocking(fd);
	if (ret < 0) {
		close(fd);
		return -EINVAL;
	}

	ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
	ev_entry->fd = fd;

	return 0;
}


struct ev_entry *ev_signal_new(void (*cb)(uint32_t, uint32_t, void *), void *data)
{
	struct ev_entry *ev_entry;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->type = EV_SIGNAL;
	ev_entry->signal_cb = cb;
	ev_entry->data = data;
	ev_entry->raw = 0;

	ev_entry_data_epoll = ev_entry->priv_data;
	sigemptyset(&ev_entry_data_epoll->signal_mask);

	return ev_entry;
}


int ev_add(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	eve_assert(ev);
	eve_assert(ev_entry);

	STAP_PROBE(libev, ev_add);

	ev_entry_data_epoll = ev_entry->priv_data;

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	if (ev_entry->raw) {
		/* type is interpreted as raw epoll_ctl event, not special
		 * internal event, no special treatment required */
		goto out;
	}

	switch (ev_entry->type) {
	case EV_TIMEOUT_ONESHOT:
		STAP_PROBE(libev, ev_add_timeout_oneshot);
		ret = ev_arm_timerfd_oneshot(ev_entry);
		if (ret != 0)
			return -EINVAL;
		break;
	case EV_TIMEOUT_PERIODIC:
		STAP_PROBE(libev, ev_add_timeout_periodic);
		ret = ev_arm_timerfd_periodic(ev_entry);
		if (ret != 0)
			return -EINVAL;
		break;
	case EV_SIGNAL:
		STAP_PROBE(libev, ev_add_signal);
		ret = ev_arm_signal(ev_entry);
		if (ret != 0)
			return -EINVAL;
		break;
	default:
		STAP_PROBE(libev, ev_add_read_write);
		// no special treatment of other entries
		break;
	}

out:

	/* FIXME: the mapping must be a one to one mapping */
	epoll_ev.events   = ev_entry_data_epoll->flags;
	epoll_ev.data.ptr = ev_entry;

	ret = epoll_ctl(ev->fd, EPOLL_CTL_ADD, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		printf("errno: %d\n", errno);
		printf("events %u\n", epoll_ev.events);
		return -EINVAL;
	}

	ev->entries++;

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

	ev->entries--;

	return 0;
}


int ev_timer_cancel(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;

	eve_assert(ev_entry);

	ret = ev_del(ev, ev_entry);
	if (ret != 0)
		return -EINVAL;

	return 0;
}


static inline void ev_process_timer_oneshot(struct ev *ev,
		                            struct ev_entry *ev_entry)
{
	ssize_t ret;
	unsigned long long missed;

	/* and now: cleanup timer specific data and
	 * finally all event specific data */
	ret = read(ev_entry->fd, &missed, sizeof(missed));
	if (ret < 0) {
		// FIXME: ok the complete error handling is some
		// what strange here. I mean the callback is called
		// and this is all we need. There is no way to inform
		// that something bad happens later where the user
		// cannot do anything
		eve_assert(0);
	}

	ev_del(ev, ev_entry);

	/* first of all - call user callback */
	STAP_PROBE(libev, trigger_timeout_oneshot);
	ev_entry->timer_cb_oneshot(ev_entry->data);
}


static inline void ev_process_timer_periodic(struct ev_entry *ev_entry)
{
	ssize_t ret;
	unsigned long long missed;

	/* and now: cleanup timer specific data and
	 * finally all event specific data */
	ret = read(ev_entry->fd, &missed, sizeof(missed));
	if (ret < 0) {
		// FIXME: ok the complete error handling is some
		// what strange here. I mean the callback is called
		// and this is all we need. There is no way to inform
		// that something bad happens later where the user
		// cannot do anything
		eve_assert(0);
	}

	/* first of all - call user callback */
	STAP_PROBE(libev, trigger_timeout_periodic);
	ev_entry->timer_cb_periodic(missed, ev_entry->data);
}


static inline void ev_process_signal(struct ev_entry *ev_entry)
{
	ssize_t ret;
	struct signalfd_siginfo sigsiginfo;

	/* and now: cleanup timer specific data and
	 * finally all event specific data */
	ret = read(ev_entry->fd, &sigsiginfo, sizeof(sigsiginfo));
	if (ret < 0) {
		// FIXME: ok the complete error handling is some
		// what strange here. I mean the callback is called
		// and this is all we need. There is no way to inform
		// that something bad happens later where the user
		// cannot do anything
		eve_assert(0);
		return;
	}
	if (ret != sizeof(sigsiginfo)) {
		pr_debug("reading signalfd too short");
		return;
	}

	STAP_PROBE2(libev, trigger_signal, sigsiginfo.ssi_signo, sigsiginfo.ssi_pid);
	ev_entry->signal_cb(sigsiginfo.ssi_signo, sigsiginfo.ssi_pid, ev_entry->data);
}


static inline void ev_process_call_internal(
		struct ev *ev, struct ev_entry *ev_entry)
{
	(void) ev;

	eve_assert(ev_entry);

	if (ev_entry->raw) {
		STAP_PROBE1(libev, trigger_raw, ev_entry->fd);
		ev_entry->fd_cb_raw(ev_entry->fd, ev_entry->type_raw, ev_entry->data);
		return;
	}

	switch (ev_entry->type) {
	case EV_READ:
	case EV_WRITE:
		STAP_PROBE1(libev, trigger_read_write, ev_entry->fd);
		ev_entry->fd_cb(ev_entry->fd, ev_entry->type, ev_entry->data);
		return;
		break;
	case EV_TIMEOUT_ONESHOT:
		ev_process_timer_oneshot(ev, ev_entry);
		break;
	case EV_TIMEOUT_PERIODIC:
		ev_process_timer_periodic(ev_entry);
		break;
	case EV_SIGNAL:
		ev_process_signal(ev_entry);
		break;
	default:
		return;
		break;
	}
	return;
}


int ev_loop(struct ev *ev, int flags)
{
	int nfds, i;
	struct epoll_event events[EVE_EPOLL_ARRAY_SIZE];

	eve_assert(ev);

	eve_assert(flags == 0); /* currently ignored */

	while (ev->entries > 0) {
		STAP_PROBE(libev, epoll_wait_enter);
		nfds = epoll_wait(ev->fd, events, EVE_EPOLL_ARRAY_SIZE, -1);
		STAP_PROBE1(libev, epoll_wait_return, nfds);
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

