#ifndef LIBEVE_H
#define LIBEVE_H

#include <sys/time.h>
#include <inttypes.h>

#define	EV_READ    (1 << 0)
#define	EV_WRITE   (1 << 1)
#define	EV_TIMEOUT (1 << 2)

#define	EV_SUCCESS 1
#define	EV_FAILURE 0

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

struct ev *ev_new(void);
void ev_free(struct ev *);
static inline unsigned int ev_size(struct ev *e) { return e->size; }

struct ev_entry *ev_entry_new(int, int, void (*cb)(int, int, void *), void *);
int ev_del(struct ev *, struct ev_entry *);
void ev_entry_free(struct ev_entry *);

struct ev_entry *ev_timer_new(struct timespec *, void (*cb)(void *), void *);
/* struct ev_event * is freed by ev_timer_cancel - user provided callbacks
 * and data not - sure. So do not dereference ev_entry afterwards */
int ev_timer_cancel(struct ev *, struct ev_entry *);

int ev_add(struct ev *, struct ev_entry *);
int ev_loop(struct ev *, uint32_t);
int ev_run_out(struct ev *);

/* auxiliary functions */
void ev_entry_set_data(struct ev_entry *, void *);
int ev_set_non_blocking(int fd);

#endif /* LIBEVE_H */
