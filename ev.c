/* Hagen Paul Pfeifer <hagen@jauu.net>
 * Public Domain Software - do what ever you want */

#include "ev.h"

#ifndef rdtscll
#define rdtscll(val) \
	__asm__ __volatile__("rdtsc" : "=A" (val))
#endif

/* gcc is smart enough to always inline static
 * defined functions that are called ones.
 * Nevertheless, we enforce this too --HGN */
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


#if defined(HAVE_EPOLL)

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <time.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <fcntl.h>

struct ev_entry_epoll {
	uint32_t flags;
};

#define	EVE_EPOLL_BACKING_STORE_HINT 64
#define EVE_EPOLL_ARRAY_SIZE 64

static struct ev *struct_ev_new_internal(void)
{
	struct ev *ev;

	ev = malloc(sizeof(struct ev));
	if (!ev)
		return NULL;

	memset(ev, 0, sizeof(struct ev));

	return ev;
}

static inline void ev_free_epoll(struct ev *ev)
{
	assert(ev);

	/* close epoll descriptor */
	close(ev->fd);

	memset(ev, 0, sizeof(struct ev));
	free(ev);
}

static inline struct ev *ev_new_epoll(void)
{
	struct ev *ev;

	ev = struct_ev_new_internal();

	ev->fd = epoll_create(EVE_EPOLL_BACKING_STORE_HINT);
	if (ev->fd < 0) {
		ev_free_epoll(ev);
		return NULL;
	}

	ev->size        = 0;
	ev->finite_loop = 0;

	return ev;
}

static struct ev_entry *struct_ev_entry_new_internal(void)
{
	struct ev_entry *ev_entry;

	ev_entry = malloc(sizeof(struct ev_entry));
	if (!ev_entry)
		return NULL;

	memset(ev_entry, 0, sizeof(struct ev_entry));

	ev_entry->priv_data = malloc(sizeof(struct ev_entry_epoll));
	if (!ev_entry->priv_data) {
		free(ev_entry);
		return NULL;
	}

	memset(ev_entry->priv_data, 0, sizeof(struct ev_entry_epoll));

	return ev_entry;
}

static inline struct ev_entry *ev_entry_new_epoll(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	struct ev_entry *ev_entry;
	struct ev_entry_epoll *ev_entry_epoll;

	assert(what == EV_READ || what == EV_WRITE);
	assert(cb);
	assert(fd >= 0);

	ev_entry = struct_ev_entry_new_internal();

	ev_entry->fd    = fd;
	ev_entry->type  = what;
	ev_entry->fd_cb = cb;
	ev_entry->data  = data;

	ev_entry_epoll = ev_entry->priv_data;

	switch (what) {
		case EV_READ:
			ev_entry_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
			break;
		case EV_WRITE:
			ev_entry_epoll->flags = EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP;
			break;
		default:
			/* cannot happen - previously catched via assert(3) */
			break;
	}

	return ev_entry;
}

static inline struct ev_entry *ev_timer_new_epoll(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	struct ev_entry *ev_entry;

	assert(timespec && cb);

	ev_entry = struct_ev_entry_new_internal();

	ev_entry->type     = EV_TIMEOUT;
	ev_entry->timer_cb = cb;
	ev_entry->data     = data;

	memcpy(&ev_entry->timespec, timespec, sizeof(struct timespec));

	return ev_entry;
}

static inline void ev_entry_free_epoll(struct ev_entry *ev_entry)
{
	assert(ev_entry->priv_data);

	free(ev_entry->priv_data);
	memset(ev_entry, 0, sizeof(struct ev_entry));
	free(ev_entry);
}

static int ev_arm_timerfd_internal(struct ev_entry *ev_entry)
{
	int ret, fd;
	struct timespec now;
	struct itimerspec new_value;
	struct ev_entry_epoll *ev_entry_epoll = ev_entry->priv_data;

	memset(&new_value, 0, sizeof(struct itimerspec));

	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (ret < 0) {
		return EV_FAILURE;
	}

	new_value.it_value.tv_sec  = now.tv_sec  + ev_entry->timespec.tv_sec;
	new_value.it_value.tv_nsec = now.tv_nsec + ev_entry->timespec.tv_nsec;

	/* timerfd_settime() cannot handle larger nsecs - catch overflow */
	if (new_value.it_value.tv_nsec >= 1000000000) {
		new_value.it_value.tv_sec++;
		new_value.it_value.tv_nsec -= 1000000000;
		assert(new_value.it_value.tv_nsec > 0);
	}

	new_value.it_interval.tv_sec  = 0;
	new_value.it_interval.tv_nsec = 0;

	fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd < 0) {
		return EV_FAILURE;
	}

	ret = timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL);
	if (ret < 0) {
		close(fd);
		return EV_FAILURE;
	}

	ev_entry_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;

	ev_entry->fd = fd;

	return EV_SUCCESS;
}

static inline int ev_add_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;
	struct ev_entry_epoll *ev_entry_epoll;

	assert(ev && ev_entry);

	ev_entry_epoll = ev_entry->priv_data;

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	if ((ev_entry->type == EV_TIMEOUT) &&
		(ev_arm_timerfd_internal(ev_entry) == EV_FAILURE)) {
		return EV_FAILURE;
	}

	/* FIXME: the mapping must be a one to one mapping */
	epoll_ev.events   = ev_entry_epoll->flags;
	epoll_ev.data.ptr = ev_entry;

	ret = epoll_ctl(ev->fd, EPOLL_CTL_ADD, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		return EV_FAILURE;
	}

	ev->size++;

	return EV_SUCCESS;
}

static inline int ev_del_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;

	assert(ev && ev_entry);

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	ret = epoll_ctl(ev->fd, EPOLL_CTL_DEL, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		return EV_FAILURE;
	}

	ev->size--;

	return EV_SUCCESS;
}

static inline int ev_timer_cancel_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;

	assert(ev_entry);
	assert(ev_entry->type == EV_TIMEOUT);

	ret = ev_del_epoll(ev, ev_entry);
	if (ret != EV_SUCCESS)
		return EV_FAILURE;

	/* close the timer fd specific descriptor */
	close(ev_entry->fd);
	ev_entry_free_epoll(ev_entry);

	return EV_SUCCESS;
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
		assert(0);
	}

	ev_del_epoll(ev, ev_entry);
	close(ev_entry->fd);
	ev_entry_free_epoll(ev_entry);
}


static inline void ev_process_call_internal(
		struct ev *ev, struct ev_entry *ev_entry)
{
	(void) ev;

	assert(ev_entry);

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

static inline int ev_loop_epoll(struct ev *ev, uint32_t flags)
{
	int nfds, i;
	struct epoll_event events[EVE_EPOLL_ARRAY_SIZE];

	assert(ev);

	(void) flags; /* currently ignored */

	while (23 && ev->size > 0) {
		nfds = epoll_wait(ev->fd, events, EVE_EPOLL_ARRAY_SIZE, -1);
		if (nfds < 0) {
			return EV_FAILURE;
		}

		/* multiplex and call the registerd callback handler */
		for (i = 0; i < nfds; i++) {
			struct ev_entry *ev_entry = (struct ev_entry *)events[i].data.ptr;
			ev_process_call_internal(ev, ev_entry);
		}

		if (ev->finite_loop)
			break;
	}

	return EV_SUCCESS;
}

static inline int ev_run_out_epoll(struct ev *ev)
{
	assert(ev);

	ev->finite_loop = 1;

	return EV_SUCCESS;
}


/* actual API methods definitions is here */
struct ev *ev_new(void)
{
	return ev_new_epoll();
}

void ev_free(struct ev *ev)
{
	return ev_free_epoll(ev);
}

struct ev_entry *ev_entry_new(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	return ev_entry_new_epoll(fd, what, cb, data);
}

struct ev_entry *ev_timer_new(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	return ev_timer_new_epoll(timespec, cb, data);
}

void ev_entry_free(struct ev_entry *ev_entry)
{
	ev_entry_free_epoll(ev_entry);
}

int ev_timer_cancel(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_timer_cancel_epoll(ev, ev_entry);
}

int ev_add(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_add_epoll(ev, ev_entry);
}

int ev_del(struct ev *ev, struct ev_entry *ev_entry)
{
	return ev_del_epoll(ev, ev_entry);
}

int ev_loop(struct ev *ev, uint32_t flags)
{
	return ev_loop_epoll(ev, flags);
}

int ev_run_out(struct ev *ev) {
	return ev_run_out_epoll(ev);
}

void ev_entry_set_data(struct ev_entry *entry, void *data)
{
	entry->data = data;
}

/* similar for all implementations, at least
 * under Linux. Solaris, AIX, etc. differs and need
 * a separate implementation */
int ev_set_non_blocking(int fd) {
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return EV_FAILURE;

	flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (flags < 0)
		return EV_FAILURE;

	return EV_SUCCESS;
}

#else
# error "No event mechanism defined (epoll, select, ..) - "
        "adjust your Makefile and define -DHAVE_EPOLL or something"
#endif


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
