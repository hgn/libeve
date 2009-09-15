#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ev.h"

void read_cb(int fd, int what, void *data)
{
	(void) fd;
	(void) what;
	(void) data;

	fprintf(stderr, "STDIN_FILENO ready for read(2)\n");
}

int main(void)
{
	int ret;
	struct ev *ev;
	struct ev_entry *ev_e;

	ev = ev_new();

	ev_e = ev_entry_new(STDIN_FILENO, EV_READ, read_cb, NULL);
	if (!ev_e) {
		fprintf(stderr, "failed to create a ev_entry object\n");
		exit(666);
	}

	ret = ev_add(ev, ev_e);
	if (ret != EV_SUCCESS) {
		fprintf(stderr, "Cannot add entry to event handler\n");
		return EXIT_FAILURE;
	}

	ev_entry_free(ev_e);

	ev_free(ev);

	return EXIT_SUCCESS;
}



/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
