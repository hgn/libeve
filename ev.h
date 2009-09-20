#ifndef EV_H
#define EV_H

#include <sys/time.h>
#include <inttypes.h>

#define	EV_READ    (1 << 0)
#define	EV_WRITE   (1 << 1)
#define	EV_TIMEOUT (1 << 2)

#define	EV_SUCCESS 1
#define	EV_FAILURE 0

struct ev {
	int fd;
	int finite_loop;
	unsigned int size;
};

struct ev_entry {
	int fd;
	int type; /* EV_READ, EV_WRITE or EV_TIMEOUT */
	struct timespec timespec;
	void (*fd_cb)(int, int, void *);
	void (*timer_cb)(void *);
	void *data;

	/* implementation specific data (e.g. for epoll, select)*/
	void *priv_data;
};

struct ev *ev_new(void);
void ev_free(struct ev *);
static inline unsigned int ev_size(struct ev *e) { return e->size; }

/* no need to free an ev_entry - it is automatically
 * when scheduled */
struct ev_entry *ev_entry_new(int, int, void (*cb)(int, int, void *), void *);
struct ev_entry *ev_timer_new(struct timespec *, void (*cb)(void *), void *);
void ev_entry_free(struct ev_entry *);

int ev_timer_cancel(struct ev *, struct ev_entry *);

int ev_add(struct ev*, struct ev_entry *);
int ev_del(struct ev*, struct ev_entry *);
int ev_loop(struct ev*, uint32_t);
int ev_run_out(struct ev*);

/* auxiliary functions */
void ev_entry_set_data(struct ev_entry *, void *);
int ev_set_non_blocking(int fd);

#endif /* EV_H */

/* vim: set tw=78 ts=4 sw=4 sts=4 ff=unix noet: */
