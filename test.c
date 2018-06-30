/* SPDX-License-Identifier: The Unlicense */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "ev.h"

#define	SLEEP_SECONDS 1
#define	ITERATIO_MAX 2

int i = 0;

void timer_cd(void *data)
{
	int ret;
	struct ev *ev = data;
	struct ev_entry *ev_e;
	struct timespec timespec = { SLEEP_SECONDS, 0};

	fprintf(stderr, "timer_cd() called %d time\n", i);

	if (i++ >= ITERATIO_MAX)
		return;

	ev_e = ev_timer_oneshot_new(&timespec, timer_cd, ev);
	if (!ev_e) {
		fprintf(stderr, "failed to create a ev_entry object\n");
		exit(666);
	}

	ret = ev_add(ev, ev_e);
	if (ret != 0) {
		fprintf(stderr, "Cannot add entry to event handler (%d)\n", i);
	}

	return;
}

struct ev_wrapper {
	struct ev *ev;
	struct ev_entry *ev_entry;
};

static void cancel_timer_cb(void *data)
{
	int ret;
	struct ev_wrapper *ev_wrapper = data;

	ret = ev_timer_cancel(ev_wrapper->ev, ev_wrapper->ev_entry);
	if (ret != 0) {
		fprintf(stderr, "failed to cancel timer\n");
		exit(EXIT_FAILURE);
	}

	ev_entry_free(ev_wrapper->ev_entry);

	return;
}

/* idea, test that timers are called in strict order and that the
 * first timer (fired after 1 seconds) cancel the 5 second timout timer */
static int do_cancel_test(struct ev *ev)
{
	int ret, flags = 0;
	struct ev_entry *eve1, *eve2;
	struct timespec timespec1 = { .tv_sec = 5, .tv_nsec = 0 };
	struct timespec timespec2 = { .tv_sec = 1, .tv_nsec = 0 };
	struct ev_wrapper *ev_wrapper;

	fprintf(stderr, "run timer cancel test ...");

	eve1 = ev_timer_oneshot_new((void *)&timespec1, (void *)timer_cd, (void *)ev);
	if (!eve1) {
		fprintf(stderr, "Failed to create a ev_entry object\n");
		exit(EXIT_FAILURE);
	}

	ret = ev_add(ev, eve1);
	if (ret != 0) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		exit(EXIT_FAILURE);
	}


	ev_wrapper = malloc(sizeof(struct ev_wrapper));
	if (!ev_wrapper) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	ev_wrapper->ev = ev;
	ev_wrapper->ev_entry = eve1;

	eve2 = ev_timer_oneshot_new((void *)&timespec2, (void *)cancel_timer_cb, (void *)ev_wrapper);
	if (!eve2) {
		fprintf(stderr, "Failed to create a ev_entry object\n");
		exit(EXIT_FAILURE);
	}

	ret = ev_add(ev, eve2);
	if (ret != 0) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		exit(EXIT_FAILURE);
	}

	ev_loop(ev, flags);

	free(ev_wrapper);

	fprintf(stderr, " passed\n");

	return 1;
}

static void test_timer(void)
{
	struct ev *ev;

	ev = ev_new(0);
	if (!ev) {
		fprintf(stderr, "Cannot create event handler\n");
		return;
	}

	do_cancel_test(ev);

	ev_destroy(ev);

}

static void cb_signal(unsigned signal_no, void *data)
{
	(void) data;

	fprintf(stderr, "caught signal %d\n", signal_no);
}


static void test_signal(void)
{
	struct ev *ev;
	int flags = 0, ret;
	struct ev_entry *ev_entry;

	ev = ev_new(0);
	if (!ev) {
		fprintf(stderr, "Cannot create event handler\n");
		return;
	}

	ev_entry = ev_signal_new(cb_signal, ev);
	if (!ev_entry) {
		fprintf(stderr, "failed to call ev_signal_new\n");
		abort();
	}
	ev_signal_catch(ev_entry, SIGHUP);
	ev_signal_catch(ev_entry, SIGINT);
	ret = ev_add(ev, ev_entry);
	if (ret != 0) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		exit(EXIT_FAILURE);
	}

	ev_loop(ev, flags);

	ev_destroy(ev);
}


int main(void)
{
	test_signal();
	//test_timer();

	return EXIT_SUCCESS;

#if 0
	/* do timer test */
	ev_e = ev_timer_new(&timespec, timer_cd, ev);
	if (!ev_e) {
		fprintf(stderr, "Failed to create a ev_entry object\n");
		goto err_timer;
	}

	ret = ev_add(ev, ev_e);
	if (ret != 0) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		goto err_add;
	}

	ev_loop(ev, flags);

	ev_free(ev);
#endif


}


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
