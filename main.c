#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ev.h"

int i = 1;

void timer_cd(void *data)
{
	int ret;
	struct ev *ev = data;
	struct ev_entry *ev_e;
	struct timespec timespec = { 0, 1000 };

	if (i++ > 1000000)
		return;

	if (i++ % 10000 == 0)
		fprintf(stdout, "iteration: %d\n", i);

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
	int ret;
	struct ev *ev;
	struct ev_entry *ev_e;
	struct timespec timespec = { 1, 0};

	ev = ev_new();

	ev_e = ev_timer_new(&timespec, timer_cd, ev);
	if (!ev_e) {
		fprintf(stderr, "failed to create a ev_entry object\n");
		exit(666);
	}

	ret = ev_add(ev, ev_e);
	if (ret != EV_SUCCESS) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		return EXIT_FAILURE;
	}

	ev_loop(ev);

	fprintf(stderr, "returned from event loop\n");

	ev_free(ev);

	return EXIT_SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
