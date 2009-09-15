#include "ev.h"

#if defined(HAVE_EPOLL)

struct ev *ev_new(void)
{
	return ev_new_epoll();
}

void ev_free(struct ev *ev)
{
	return ev_free_epoll(ev);
}

struct ev_entry *ev_entry_new(int fd, int what, void (*cb)(int, int, void *), void *data)
{
	return ev_entry_new_epoll(fd, what, cb, data);
}

struct ev_entry *ev_timer_new(struct timespec *timespec, void (*cb)(void *), void *data)
{
	return ev_timer_new_epoll(timespec, cb, data);
}

void ev_entry_free(struct ev_entry *ev_entry)
{
	ev_entry_free_epoll(ev_entry);
}

int ev_add(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_add_epoll(ev, ev_entry);
}

int ev_del(struct ev *ev, struct ev_entry *ev_entry)
{
	return ev_del_epoll(ev, ev_entry);
}

int ev_loop(struct ev *ev)
{
	return ev_loop_epoll(ev);
}

int ev_run_out(struct ev *ev) {
	return ev_run_out_epoll(ev);
}

#else
# error "No event mechanism defined (epoll, select, ..) - configure your Makefile"
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

#include "ev.h"

static struct ev *struct_ev_new_internal(void)
{
	struct ev *ev;

	ev = malloc(sizeof(struct ev));
	if (!ev)
		return NULL;

	memset(ev, 0, sizeof(struct ev));

	return ev;
}

void ev_free_epoll(struct ev *ev)
{
	assert(ev);

	/* close epoll descriptor */
	close(ev->fd);

	memset(ev, 0, sizeof(struct ev));
	free(ev);
}

struct ev *ev_new_epoll(void)
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

struct ev_entry *ev_entry_new_epoll(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	struct ev_entry *ev_entry;
	struct ev_entry_epoll *ev_entry_epoll;

	assert(what == EV_READ || what == EV_WRITE);
	assert(cb);

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
			break;
	}

	return ev_entry;
}

struct ev_entry *ev_timer_new_epoll(struct timespec *timespec,
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

void ev_entry_free_epoll(struct ev_entry *ev_entry)
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

	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (ret < 0) {
		return EV_FAILURE;
	}

	new_value.it_value.tv_sec  = now.tv_sec  + ev_entry->timespec.tv_sec;
	new_value.it_value.tv_nsec = now.tv_nsec + ev_entry->timespec.tv_nsec;

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

int ev_add_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;
	struct ev_entry_epoll *ev_entry_epoll;

	assert(ev && ev_entry);

	ev_entry_epoll = ev_entry->priv_data;

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	if ((ev_entry->type == EV_TIMEOUT) &&
		(ev_arm_timerfd_internal(ev_entry) == EV_FAILURE))
		return EV_FAILURE;

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

int ev_del_epoll(struct ev *ev, struct ev_entry *ev_entry)
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


static void ev_process_call_internal(struct ev *ev, struct ev_entry *ev_entry)
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
			ev_entry->timer_cb(ev_entry->data);
			break;
		default:
			return;
			break;
	}
	return;
}

int ev_loop_epoll(struct ev *ev)
{
	int nfds, i;
	struct epoll_event events[EVE_EPOLL_ARRAY_SIZE];

	assert(ev);

	while (23) {
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

int ev_run_out_epoll(struct ev *ev)
{
	assert(ev);

	ev->finite_loop = 1;

	return EV_SUCCESS;
}

#endif

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
