#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

	ev_e = ev_timer_new(&timespec, timer_cd, ev);
	if (!ev_e) {
		fprintf(stderr, "failed to create a ev_entry object\n");
		exit(666);
	}

	ret = ev_add(ev, ev_e);
	if (ret != EV_SUCCESS) {
		fprintf(stderr, "Cannot add entry to event handler (%d)\n", i);
	}

	return;
}

int main(void)
{
	int ret, flags = 0;
	struct ev *ev;
	struct ev_entry *ev_e;
	struct timespec timespec = { SLEEP_SECONDS, 0};

	ev = ev_new();
	if (!ev) {
		fprintf(stderr, "Cannot create event handler\n");
		goto err;
	}

	/* do timer test */
	ev_e = ev_timer_new(&timespec, timer_cd, ev);
	if (!ev_e) {
		fprintf(stderr, "Failed to create a ev_entry object\n");
		goto err_timer;
	}

	ret = ev_add(ev, ev_e);
	if (ret != EV_SUCCESS) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		goto err_add;
	}

	ev_loop(ev, flags);

	ev_free(ev);

	return EXIT_SUCCESS;


err_add:
	ev_entry_free(ev_e);
err_timer:
	ev_free(ev);
err:
	return EXIT_FAILURE;
}


/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
