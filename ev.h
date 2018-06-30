/* SPDX-License-Identifier: The Unlicense */

#ifndef LIBEVE_H
#define LIBEVE_H

#include <sys/time.h>
#include <inttypes.h>

#define	EV_READ             (1 << 0)
#define	EV_WRITE            (1 << 1)
#define	EV_TIMEOUT_ONESHOT  (1 << 2)
#define	EV_TIMEOUT_PERIODIC (1 << 3)

#define EV_CLOEXEC (1 << 0)

/*
 * Forward declaration - ev objects are fully opaque to
 * callers. Access is always done via access functions.
 * Just keep in mind: ev is the object you usualy needs one,
 * the main object. For each registered event like timer or
 * file descriptor you corresponding ev_entry object is
 * required.
 */
struct ev;
struct ev_entry;

/**
 * ev_new - initialize a new event object, eve main data structure
 *
 * It return the new ev object or NULL in the case of an error.
 */
struct ev *ev_new(int flags);

/**
 *
 * In the case of an error an negative errno value is returned.
 * It is up to the caller to free ev_entry data structure.
 */
int ev_add(struct ev *, struct ev_entry *);
int ev_loop(struct ev *, int);
int ev_run_out(struct ev *);


/**
 * ev_destroy - deallocate ev structure
 * @ev: pointer instance of ev object
 *
 * Shutdown, close and free all associated resourches of ev. This function
 * it the counterpart to ev_new() and should at least be called at
 * program shutdown or restart.
 *
 * Keep in mind that the caller is responsible to deallocate all registered
 * ev_event data structures, close file descriptors, etc. This cannot be done
 * by ev_destroy().
 *
 * This function cannot fail and thus return no return status.
 */
void ev_destroy(struct ev *);

/**
 * ev_entries - return number of active event entries
 * @ev: pointer instance of ev object
 *
 * This function returns the number of active event
 * entries, like timers, descriptors or signals. With
 * each ev_event_add the counter is incremented and vice
 * versa for delete operations.
 *
 * This function cannot fail.
 */
unsigned long long ev_entries(struct ev *e);


/* ev, auxiliary functions */
/* use this function if you want to put
 * the epoll fd into another epoll structure. Rarelly
 * needed, but ... how knows */
int ev_fd(struct ev *ev);

struct ev_entry *ev_entry_new(int, int, void (*cb)(int, int, void *), void *);
int ev_del(struct ev *, struct ev_entry *);
void ev_entry_free(struct ev_entry *);


struct ev_entry *ev_timer_oneshot_new(struct timespec *, void (*cb)(void *), void *);

/* struct ev_event * is freed by ev_timer_cancel - user provided callbacks
 * and data not - sure. So do not dereference ev_entry afterwards */
int ev_timer_oneshot_cancel(struct ev *, struct ev_entry *);

struct ev_entry *ev_timer_periodic_new(struct timespec *, void (*cb)(void *), void *);


/*
 * Signal handling is a little bit different, for files & sockets
 * as well as timers there are unique, non-shared resourches. Signals
 * on the other hand are different: there is a global, per process mask
 *
 * signal new clears and come with a fresh mask
 *
 * Don't use the signal handling code if you handle signal handler
 * manually somewhere else in the program. Both signal handling routines
 * will conflict.
 */
//struct ev_entry *ev_signal_new(struct signal_mask, );

//int ev_signal_add(int signo);



/* auxiliary functions */
void ev_entry_set_data(struct ev_entry *, void *);
int ev_set_non_blocking(int fd);

#endif /* LIBEVE_H */
