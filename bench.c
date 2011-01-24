#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

#include "ev.h"

#define	PIPES 500
#define	SLEEP_TIME 2

int iterations;

static int *pipes;
static int pipes_no;

static struct ev *ev;

static void read_cd(int fd, int what, void *data)
{
	struct timeval *tv1, tv2;

	(void) what;
	(void) fd;

	tv1 = (struct timeval *)data;

	gettimeofday(&tv2, NULL);

	fprintf(stdout, "%ld microseconds for %d pipes (%d for read/write pipe count)\n",
			((tv2.tv_sec - tv1->tv_sec) * 1000000) + (tv2.tv_usec - tv1->tv_usec),
			pipes_no, pipes_no * 2);

	exit(EXIT_SUCCESS);
}

static void process_child(void)
{
	int i;

	/* close read side of pipe */
	for (i = 0; i < pipes_no; i += 2) {
		close(pipes[i]);
	}

	for (i = 1; i < pipes_no; i += 2)
		;

	write(pipes[i - 2], "x", 1);
}


int main(int ac, char **av)
{
	int i, ret, flags = 0; pid_t pid;
	struct ev_entry *ev_e;
	struct timeval tv1;

	if (ac != 2) {
		fprintf(stderr, "Usage: %s <pipes>\n", av[0]);
		exit(EXIT_FAILURE);
	}

	pipes_no = atoi(av[1]);
	if (pipes_no < 0) {
		fprintf(stderr, "pipes no out of valid range\n");
		exit(EXIT_FAILURE);
	}

	pipes = malloc(pipes_no * sizeof(int) * 2);
	if (!pipes) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	ev = ev_new();
	if (!ev) {
		fprintf(stderr, "Cannot create event handler\n");
		exit(666);
	}

	for (i = 0; i < pipes_no; i += 2) {
		ret = pipe(&pipes[i]);
		if (ret < 0) {
			perror("pipe");
			exit(666);
		}
	}

	pid = fork();
	switch (pid) {
		case -1:
			perror("fork error");
			exit(EXIT_FAILURE);
		case 0:
			break;
		default:
			process_child();
			exit(EXIT_SUCCESS);
			break;
	}

	for (i = 0; i < pipes_no; i+= 2) {
		ret = ev_set_non_blocking(pipes[i]);
		if (ret != EV_SUCCESS) {
			exit(EXIT_FAILURE);
		}

		ev_e = ev_entry_new(pipes[i], EV_READ, read_cd, &tv1);
		if (!ev_e) {
			fprintf(stderr, "Cannot create event entry\n");
			exit(EXIT_FAILURE);
		}

		ret = ev_add(ev, ev_e);
		if (ret != EV_SUCCESS) {
			fprintf(stderr, "Cannot add entry to event handler\n");
			exit(EXIT_FAILURE);
		}
	}

	sleep(SLEEP_TIME);

	gettimeofday(&tv1, NULL);
	ev_loop(ev, flags);

	ev_free(ev);

	return EXIT_SUCCESS;
}
