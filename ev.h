/* SPDX-License-Identifier: The Unlicense */

#ifndef LIBEVE_H
#define LIBEVE_H

#include <sys/time.h>
#include <inttypes.h>

#define	EV_READ             (1 << 0)
#define	EV_WRITE            (1 << 1)
#define	EV_TIMEOUT_ONESHOT  (1 << 2)
#define	EV_TIMEOUT_PERIODIC (1 << 3)
#define	EV_SIGNAL           (1 << 4)

#define EV_CLOEXEC (1 << 0)

/*
 * Forward declaration - ev objects are fully opaque to callers. Access is
 * always done via access functions.  Just keep in mind: ev is the object you
 * usualy needs one, the main object. For each registered event like timer or
 * file descriptor you corresponding ev_entry object is required.
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
 * Add ev_event to the main ev event structure
 *
 * This registers all events (fd, signals, timer) at the main structure and
 * must be called before ev_loop.
 *
 * In the case of an error an negative errno value is returned.  It is up to
 * the caller to free ev_entry data structure.
 */
int ev_add(struct ev *, struct ev_entry *);


/**
 * Main event loop start function
 *
 * This function will call epoll_wait and will block until event is triggered.
 * Please call this at the end after every ev_event's are registered.
 */
int ev_loop(struct ev *, int);



/* To end the processing loop
 *
 * Keep in mind: this will not free any memory, nor does this function call
 * ev_del to deregister.  It just break out after an event it triggered.
 *
 * This function is probably not what you want to use
 */
int ev_run_out(struct ev *);


/**
 * ev_entries - return number of active event entries
 * @ev: pointer instance of ev object
 *
 * This function returns the number of active event entries, like timers,
 * descriptors or signals. With each ev_event_add the counter is incremented
 * and vice versa for delete operations.
 *
 * This function cannot fail.
 */
unsigned long long ev_entries(struct ev *e);


/**
 * use this function if you want to put the epoll fd into another epoll
 * structure. Rarelly needed, but ... how knows
 */
int ev_fd(struct ev *ev);


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
 * ev_entry new provides api to register a raw filedescriptor (e.g. socket)
 * for later use in epoll set. The arguments:
 *
 * 1) the filedescriptor
 * 2) EV_READ or EV_WRITE
 * 3) a callback, called if fd is ready for read or write
 * 4) a private data hand over to the caller within the callback
 *
 * The callback protoype is similar:
 *
 * 1) the filedescriptor
 * 2) EV_READ or EV_WRITE
 * 3) the private data pointer, registered at ev_entry_new time
 *
 * Warning: do not throw exceptions or call longjmp from a callback.
 *
 * The next steps is to register this entry at the main loop wia
 * ev_add()
 *
 * This function return NULL in the case of an error or a pointer
 * to a newly allocated struct.
 */
struct ev_entry *ev_entry_new(int, int, void (*cb)(int, int, void *), void *);


/**
 * Deregister event from main event loop
 *
 * Please make sure to call ev_entry_free() to remove all allocated
 * resourches to free memory.
 *
 * Return 0 in the case of sucess, otherwise a negative error code.
 */
int ev_del(struct ev *, struct ev_entry *);


/**
 * Deallocate resourcheso of ev_eventy
 *
 * This is the counterpart of ev_entry_new(), ev_timer_oneshot_new(),
 * ev_timer_periodic_new() and ev_signal_new() and must be called to free
 * associated memory.
 */
void ev_entry_free(struct ev_entry *);






/**
 * Create new oneshot timer
 *
 * Just arm a timer for one shot, after the callback the timer is not re-added
 * to the main loop automatically.  The caller is responsible to free
 * resourches afterwards with ev_entry_free()
 *
 * Warning: do not throw exceptions or call longjmp from a callback.
 */
struct ev_entry *ev_timer_oneshot_new(struct timespec *, void (*cb)(void *), void *);


/**
 * Start periodic timer
 *
 * Ater timespec time the user provided callack cb is called. To end the timer
 * ev_timer_cancel() must be called. Normally followed by ev_entry_free()
 *
 * Warning: do not throw exceptions or call longjmp from a callback.
 *
 * Returns NULL in case the case of an error
 */
struct ev_entry *ev_timer_periodic_new(struct timespec *, void (*cb)(void *), void *);


/*
 * struct ev_event * is freed by ev_timer_cancel - user provided callbacks
 * and data not - sure. So do not dereference ev_entry afterwards
 *
 * Make sure that ever you cancel the timer you call ev_entry_free()
 *
 */
int ev_timer_cancel(struct ev *, struct ev_entry *);




/**
 * Signal handling is a little bit different, for files & sockets as well as
 * timers there are unique, non-shared resourches. Signals on the other hand
 * are different: there is a global, per process mask
 *
 * signal new clears and come with a fresh mask
 *
 * Don't use the signal handling code if you handle signal handler manually
 * somewhere else in the program. Both signal handling routines will conflict.
 *
 * The registered callback prototype arguments are:
 *
 * 1) the signal number
 * 2) the pid of the sending process, 0 if send from local process
 * 3) the registered private data structure (last elemetn to ev_signal_new)
 *
 * The function returns a NULL pointer if something failed.
 */
struct ev_entry *ev_signal_new(void (*cb)(uint32_t, uint32_t, void *), void *);


/**
 * ev_signal_catch - register signal to be catches
 *
 * After ev_signal_new no signal is catched. It is up to the user
 * to subsequent register signals to be catched. This function provides
 * the interface for it.
 *
 * ev_signal_catch can be called multiple time if several signals must
 * be catches. The callback handler registered with ev_signal_new() hand
 * over the particular signal. Thus the user can switch/case in the callback
 * handler accodingly
 *
 * Function returns 0 in the case of success, negative error code otherwise.
 *
 */
int ev_signal_catch(struct ev_entry *, int signo);




/**
 * set filedescriptor in non-blocking mode
 *
 * All descriptors registered at epoll must be operate in non-blocking
 * way. Often you can get a non-blocking descriptor with the right options
 * for some syscalls. If not this function can be used.
 *
 * This function return the 0 in the case of success or negative value
 * if something went wront.
 */
int ev_set_non_blocking(int fd);

/* auxiliary functions */
void ev_entry_set_data(struct ev_entry *, void *);


#endif /* LIBEVE_H */
