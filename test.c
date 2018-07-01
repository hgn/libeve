/* SPDX-License-Identifier: The Unlicense */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

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


static void cb_signal(uint32_t signal_no, uint32_t pid, void *data)
{
	(void) data;

	switch (signal_no) {
	case SIGINT:
		fprintf(stderr, "caught SIGINT from pid %u\n", pid);
		break;
	case SIGQUIT:
		fprintf(stderr, "caught SIGQUIT from pid %u\n", pid);
		break;
	default:
		fprintf(stderr, "caught signal %d from pid %u\n", signal_no, pid);
		break;
	}
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
	ev_signal_catch(ev_entry, SIGQUIT); // ^ backslash
	ev_signal_catch(ev_entry, SIGINT);  // ^C
	ret = ev_add(ev, ev_entry);
	if (ret != 0) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		exit(EXIT_FAILURE);
	}

	ev_loop(ev, flags);

	ev_destroy(ev);
}


struct ctx_timer {
	struct ev_entry *eve;
	struct ev *ev;

	unsigned periodic_runs;
};


struct ctx_timer *ctx_timer_new(void)
{
	struct ctx_timer *ctxo;
	ctxo = malloc(sizeof(*ctxo));
	if (!ctxo) abort();
	memset(ctxo, 0, sizeof(*ctxo));
	return ctxo;
}


void callback_oneshot(void *data)
{
	struct ctx_timer *ctxo = data;

	ev_entry_free(ctxo->eve);
	free(ctxo);

	fprintf(stderr, "callback called\n");
}


static void test_timer_oneshot(void)
{
	struct ev *ev;
	int flags = 0, ret;
	struct ev_entry *eve;
	struct ctx_timer *ctxo;
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

	fprintf(stderr, "Test: oneshot timer\n");

	ev = ev_new(0);
	if (!ev) {
		fprintf(stderr, "Cannot create event handler\n");
		return;
	}

	ctxo = ctx_timer_new();
	ctxo->ev = ev;

	eve = ev_timer_oneshot_new(&ts, callback_oneshot, ctxo);
	if (!eve) {
		fprintf(stderr, "Failed to create a ev_entry object\n");
		exit(EXIT_FAILURE);
	}

	ctxo->eve = eve;

	ret = ev_add(ev, eve);
	if (ret != 0) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		exit(EXIT_FAILURE);
	}

	// ev_loop will run until the timeout is fired. Which
	// in turn is the last event, which will end the ev loop
	ev_loop(ev, flags);

	ev_destroy(ev);
}


void callback_timer_periodic(void *data)
{
	int ret;
	struct ctx_timer *ctxo = data;

	fprintf(stderr, "callback timer periodic called %d\n", ctxo->periodic_runs);

	ctxo->periodic_runs--;
	if (ctxo->periodic_runs == 0) {
		// finish, enough testing
		ret = ev_timer_cancel(ctxo->ev, ctxo->eve);
		if (ret < 0) {
			fprintf(stderr, "failed to cancel timer\n");
			exit(EXIT_FAILURE);
		}
		ev_entry_free(ctxo->eve);
		free(ctxo);
	}
}


static void test_timer_periodic(void)
{
	struct ev *ev;
	int flags = 0, ret;
	struct ev_entry *eve;
	struct ctx_timer *ctxo;
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

	fprintf(stderr, "Test: periodic timer\n");

	ev = ev_new(0);
	if (!ev) {
		fprintf(stderr, "Cannot create event handler\n");
		return;
	}

	ctxo = ctx_timer_new();
	ctxo->ev = ev;
	ctxo->periodic_runs = 5;

	eve = ev_timer_periodic_new(&ts, callback_timer_periodic, ctxo);
	if (!eve) {
		fprintf(stderr, "Failed to create a ev_entry object\n");
		exit(EXIT_FAILURE);
	}
	ctxo->eve = eve;

	ret = ev_add(ev, eve);
	if (ret != 0) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		exit(EXIT_FAILURE);
	}

	// ev_loop will run until the timeout is fired. Which
	// in turn is the last event, which will end the ev loop
	ev_loop(ev, flags);

	ev_destroy(ev);
}


int main(void)
{
	test_signal();
	//test_timer_oneshot();
	//test_timer_periodic();
	//test_timer();

	return EXIT_SUCCESS;


}

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
