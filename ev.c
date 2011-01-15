/* Hagen Paul Pfeifer <hagen@jauu.net>
 * Public Domain Software - do what ever you want */

#include "ev.h"

#ifndef rdtscll
#define rdtscll(val) \
	__asm__ __volatile__("rdtsc" : "=A" (val))
#endif

/* gcc is smart enough to always inline static
 * defined functions that are called ones.
 * Nevertheless, we enforce this too --HGN */
#undef __always_inline
#if __GNUC_PREREQ (3,2)
# define __always_inline __inline __attribute__ ((__always_inline__))
#else
# define __always_inline __inline
#endif

#if !defined(likely) && !defined(unlikely)
# define likely(x)   __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#if !defined(ARRAY_SIZE)
# define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#if defined(LIBEVE_DEBUG)
#define pr_debug(fmt_str, ...) \
	fprintf(stderr, fmt_str, ##__VA_ARGS__)
#else
#define pr_debug(fmt_str, ...) \
        ({ if (0) fprintf(stderr, fmt_str, ##__VA_ARGS__); 0; })
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>

/* FIXME: check for wrong subtraction/addition operation of struct timespec */

/* cmp: <, <=, >, >= or == */
#define timespec_cmp(tvp, uvp, cmp)               \
	(((tvp)->tv_sec == (uvp)->tv_sec) ?       \
	 ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :    \
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define timespec_add(res, vvp, uvp)                       \
do {                                                      \
	(res)->tv_sec  = (vvp)->tv_sec  + (uvp)->tv_sec;  \
	(res)->tv_nsec = (vvp)->tv_nsec + (uvp)->tv_nsec; \
	if ((res)->tv_nsec >= 1000000000) {               \
		(res)->tv_sec++;                          \
		(res)->tv_nsec -= 1000000000;             \
	}                                                 \
} while (0)

#define timespec_sub(res, vvp, uvp)                       \
do {                                                      \
	(res)->tv_sec = (vvp)->tv_sec - (uvp)->tv_sec;    \
	(res)->tv_nsec = (vvp)->tv_nsec - (uvp)->tv_nsec; \
	if ((res)->tv_nsec < 0) {                         \
		(res)->tv_sec--;                          \
		(res)->tv_nsec += 1000000000;             \
	}                                                 \
} while (0)

static inline int timespec_equal(const struct timespec *a,
                                 const struct timespec *b)
{
        return (a->tv_sec == b->tv_sec) && (a->tv_nsec == b->tv_nsec);
}

static struct ev *struct_ev_new_internal(void)
{
	struct ev *ev;

	ev = malloc(sizeof(*ev));
	if (!ev)
		return NULL;

	memset(ev, 0, sizeof(*ev));

	return ev;
}

inline void ev_entry_set_data(struct ev_entry *entry, void *data)
{
	entry->data = data;
}

int ev_run_out(struct ev *ev)
{
	assert(ev);
	ev->break_loop = 1;
	return EV_SUCCESS;
}

/* similar for all implementations, at least
 * under Linux. Solaris, AIX, etc. differs and need
 * a separate implementation */
int ev_set_non_blocking(int fd) {
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return EV_FAILURE;

	flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (flags < 0)
		return EV_FAILURE;

	return EV_SUCCESS;
}


#if defined(HAVE_EPOLL)

#include <sys/epoll.h>
#include <sys/timerfd.h>

struct ev_entry_data_epoll {
	uint32_t flags;
};

#define	EVE_EPOLL_BACKING_STORE_HINT 64
#define EVE_EPOLL_ARRAY_SIZE 64

static inline void ev_free_epoll(struct ev *ev)
{
	assert(ev);

	/* close epoll descriptor */
	close(ev->fd);

	memset(ev, 0, sizeof(struct ev));
	free(ev);
}

static inline struct ev *ev_new_epoll(void)
{
	struct ev *ev;

	ev = struct_ev_new_internal();
	if (!ev)
		return NULL;

	ev->fd = epoll_create(EVE_EPOLL_BACKING_STORE_HINT);
	if (ev->fd < 0) {
		ev_free_epoll(ev);
		return NULL;
	}

	ev->size        = 0;
	ev->break_loop = 0;

	return ev;
}

static struct ev_entry *ev_entry_new_epoll_internal(void)
{
	struct ev_entry *ev_entry;

	ev_entry = malloc(sizeof(struct ev_entry));
	if (!ev_entry)
		return NULL;

	memset(ev_entry, 0, sizeof(struct ev_entry));

	ev_entry->priv_data = malloc(sizeof(struct ev_entry_data_epoll));
	if (!ev_entry->priv_data) {
		free(ev_entry);
		return NULL;
	}

	memset(ev_entry->priv_data, 0, sizeof(struct ev_entry_data_epoll));

	return ev_entry;
}

static inline struct ev_entry *ev_entry_new_epoll(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	struct ev_entry *ev_entry;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	assert(what == EV_READ || what == EV_WRITE);
	assert(cb);
	assert(fd >= 0);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->fd    = fd;
	ev_entry->type  = what;
	ev_entry->fd_cb = cb;
	ev_entry->data  = data;

	ev_entry_data_epoll = ev_entry->priv_data;

	switch (what) {
		case EV_READ:
			ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
			break;
		case EV_WRITE:
			ev_entry_data_epoll->flags = EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP;
			break;
		default:
			/* cannot happen - previously catched via assert(3) */
			break;
	}

	return ev_entry;
}

static inline struct ev_entry *ev_timer_new_epoll(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	struct ev_entry *ev_entry;

	assert(timespec && cb);

	ev_entry = ev_entry_new_epoll_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->type     = EV_TIMEOUT;
	ev_entry->timer_cb = cb;
	ev_entry->data     = data;

	memcpy(&ev_entry->timespec, timespec, sizeof(struct timespec));

	return ev_entry;
}

static inline void ev_entry_free_epoll(struct ev_entry *ev_entry)
{
	assert(ev_entry);
	assert(ev_entry->priv_data);

	free(ev_entry->priv_data);
	memset(ev_entry, 0, sizeof(struct ev_entry));
	free(ev_entry);
}

static int ev_arm_timerfd_internal(struct ev_entry *ev_entry)
{
	int ret, fd;
	struct timespec now;
	struct itimerspec new_value;
	struct ev_entry_data_epoll *ev_entry_data_epoll = ev_entry->priv_data;

	memset(&new_value, 0, sizeof(struct itimerspec));

	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (ret < 0) {
		return EV_FAILURE;
	}

	new_value.it_value.tv_sec  = now.tv_sec  + ev_entry->timespec.tv_sec;
	new_value.it_value.tv_nsec = now.tv_nsec + ev_entry->timespec.tv_nsec;

	/* timerfd_settime() cannot handle larger nsecs - catch overflow */
	if (new_value.it_value.tv_nsec >= 1000000000) {
		new_value.it_value.tv_sec++;
		new_value.it_value.tv_nsec -= 1000000000;
		assert(new_value.it_value.tv_nsec > 0);
	}

	new_value.it_interval.tv_sec  = 0;
	new_value.it_interval.tv_nsec = 0;

	fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd < 0) {
		return EV_FAILURE;
	}

	ret = timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL);
	if (ret < 0) {
		close(fd);
		return EV_FAILURE;
	}

	ev_entry_data_epoll->flags = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;

	ev_entry->fd = fd;

	return EV_SUCCESS;
}

static inline int ev_add_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;
	struct ev_entry_data_epoll *ev_entry_data_epoll;

	assert(ev);
	assert(ev_entry);

	ev_entry_data_epoll = ev_entry->priv_data;

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	if ((ev_entry->type == EV_TIMEOUT) &&
			(ev_arm_timerfd_internal(ev_entry) == EV_FAILURE)) {
		return EV_FAILURE;
	}

	/* FIXME: the mapping must be a one to one mapping */
	epoll_ev.events   = ev_entry_data_epoll->flags;
	epoll_ev.data.ptr = ev_entry;

	ret = epoll_ctl(ev->fd, EPOLL_CTL_ADD, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		return EV_FAILURE;
	}

	ev->size++;

	return EV_SUCCESS;
}

static inline int ev_del_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct epoll_event epoll_ev;

	assert(ev && ev_entry);

	memset(&epoll_ev, 0, sizeof(struct epoll_event));

	ret = epoll_ctl(ev->fd, EPOLL_CTL_DEL, ev_entry->fd, &epoll_ev);
	if (ret < 0) {
		return EV_FAILURE;
	}

	ev->size--;

	return EV_SUCCESS;
}

static inline int ev_timer_cancel_epoll(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;

	assert(ev_entry);
	assert(ev_entry->type == EV_TIMEOUT);

	ret = ev_del_epoll(ev, ev_entry);
	if (ret != EV_SUCCESS)
		return EV_FAILURE;

	/* close the timer fd specific descriptor */
	close(ev_entry->fd);
	ev_entry_free_epoll(ev_entry);

	return EV_SUCCESS;
}

static inline void ev_process_call_epoll_timeout(
		struct ev *ev, struct ev_entry *ev_entry)
{
	ssize_t ret;
	int64_t time_buf;

	/* first of all - call user callback */
	ev_entry->timer_cb(ev_entry->data);

	/* and now: cleanup timer specific data and
	 * finally all event specific data */
	ret = read(ev_entry->fd, &time_buf, sizeof(int64_t));
	if ((ret < (ssize_t)sizeof(int64_t)) ||
			(time_buf > 1)) {
		/* failure - should not happens: kernel bug */
		assert(0);
	}

	ev_del_epoll(ev, ev_entry);
	close(ev_entry->fd);
	ev_entry_free_epoll(ev_entry);
}


static inline void ev_process_call_internal(
		struct ev *ev, struct ev_entry *ev_entry)
{
	(void) ev;

	assert(ev_entry);

	switch (ev_entry->type) {
		case EV_READ:
		case EV_WRITE:
			ev_entry->fd_cb(ev_entry->fd, ev_entry->type, ev_entry->data);
			return;
			break;
		case EV_TIMEOUT:
			ev_process_call_epoll_timeout(ev, ev_entry);
			break;
		default:
			return;
			break;
	}
	return;
}

static inline int ev_loop_epoll(struct ev *ev, uint32_t flags)
{
	int nfds, i;
	struct epoll_event events[EVE_EPOLL_ARRAY_SIZE];

	assert(ev);

	(void) flags; /* currently ignored */

	while (ev->size > 0) {
		nfds = epoll_wait(ev->fd, events, EVE_EPOLL_ARRAY_SIZE, -1);
		if (nfds < 0) {
			return EV_FAILURE;
		}

		/* multiplex and call the registerd callback handler */
		for (i = 0; i < nfds; i++) {
			struct ev_entry *ev_entry = (struct ev_entry *)events[i].data.ptr;
			ev_process_call_internal(ev, ev_entry);
		}

		if (ev->break_loop)
			break;
	}

	return EV_SUCCESS;
}


/* actual epoll/timer_fd API methods definitions is here */
struct ev *ev_new(void)
{
	return ev_new_epoll();
}

void ev_free(struct ev *ev)
{
	return ev_free_epoll(ev);
}

struct ev_entry *ev_entry_new(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	return ev_entry_new_epoll(fd, what, cb, data);
}

struct ev_entry *ev_timer_new(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	return ev_timer_new_epoll(timespec, cb, data);
}

void ev_entry_free(struct ev_entry *ev_entry)
{
	ev_entry_free_epoll(ev_entry);
}

int ev_timer_cancel(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_timer_cancel_epoll(ev, ev_entry);
}

int ev_add(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_add_epoll(ev, ev_entry);
}

int ev_del(struct ev *ev, struct ev_entry *ev_entry)
{
	return ev_del_epoll(ev, ev_entry);
}

int ev_loop(struct ev *ev, uint32_t flags)
{
	return ev_loop_epoll(ev, flags);
}


#elif defined(HAVE_SELECT)

/* According to POSIX.1-2001 */
#include <sys/select.h>
/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

enum rbtree_color { RED, BLACK };

struct rbtree_node {

	struct rbtree_node *left;
	struct rbtree_node *right;
	struct rbtree_node *parent;

	/* key is of type struct timespec * */
	void *key;
	/* data is of type struct ev_entry * */
	void *data;

	enum rbtree_color color;
};

struct ev_entry_data_select {
	uint32_t flags;
	struct rbtree_node *node;
};

struct rbtree {
	struct rbtree_node *root;
	int (*compare)(void *, void *);
	size_t size;
};


struct rbtree *rbtree_init(int (*cmp)(void *, void *));

struct rbtree_node *rbtree_lookup(struct rbtree *, void *key);
struct rbtree_node *rbtree_insert(struct rbtree *, void *key, void *data);
struct rbtree_node *rbtree_delete(struct rbtree *, void *key);
struct rbtree_node *rbtree_delete_by_node(struct rbtree* t, struct rbtree_node *n);

struct rbtree_node *rbtree_lookup_max_node(struct rbtree_node *);
struct rbtree_node *rbtree_lookup_min_node(struct rbtree_node *);

size_t rbtree_size(struct rbtree *);
struct rbtree_node *rbtree_node_alloc(void);
void rbtree_node_free(struct rbtree_node *);
/* deletes rbtree only, rbtree_node must be deleted before */
void rbtree_rbtree_free(struct rbtree *);

void rbtree_travers(struct rbtree *);

static struct rbtree_node *sibling(struct rbtree_node *n);
static struct rbtree_node *uncle(struct rbtree_node *n);
static enum rbtree_color node_color(struct rbtree_node *n);

static void rotate_left(struct rbtree *, struct rbtree_node *);
static void rotate_right(struct rbtree *, struct rbtree_node *);

/* forward declarations */
static void replace_node(struct rbtree *, struct rbtree_node *, struct rbtree_node *);
static void insert_1(struct rbtree *, struct rbtree_node *);
static void insert_2(struct rbtree *, struct rbtree_node *);
static void insert_3(struct rbtree *, struct rbtree_node *);
static void insert_4(struct rbtree *, struct rbtree_node *);
static void insert_5(struct rbtree *, struct rbtree_node *);
static void delete_1(struct rbtree *, struct rbtree_node *);
static void delete_2(struct rbtree *, struct rbtree_node *);
static void delete_3(struct rbtree *, struct rbtree_node *);
static void delete_4(struct rbtree *, struct rbtree_node *);
static void delete_5(struct rbtree *, struct rbtree_node *);
static void delete_6(struct rbtree *, struct rbtree_node *);

static struct rbtree_node* grandparent(struct rbtree_node* n) {

	assert(n);
	assert(n->parent);
	assert(n->parent->parent);

	return n->parent->parent;
}

static void delete_1(struct rbtree* t, struct rbtree_node* n)
{
	if (n->parent == NULL)
		return;
	else
		delete_2(t, n);
}


static void delete_2(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(sibling(n)) == RED) {
		n->parent->color = RED;
		sibling(n)->color = BLACK;
		if (n == n->parent->left)
			rotate_left(t, n->parent);
		else
			rotate_right(t, n->parent);
	}
	delete_3(t, n);
}


static void delete_3(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(n->parent) == BLACK &&
			node_color(sibling(n)) == BLACK &&
			node_color(sibling(n)->left) == BLACK &&
			node_color(sibling(n)->right) == BLACK)
	{
		sibling(n)->color = RED;
		delete_1(t, n->parent);
	}
	else
		delete_4(t, n);
}


static void delete_4(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(n->parent) == RED &&
			node_color(sibling(n)) == BLACK &&
			node_color(sibling(n)->left) == BLACK &&
			node_color(sibling(n)->right) == BLACK)
	{
		sibling(n)->color = RED;
		n->parent->color = BLACK;
	}
	else
		delete_5(t, n);
}


static void delete_5(struct rbtree* t, struct rbtree_node* n)
{
	if (n == n->parent->left &&
			node_color(sibling(n)) == BLACK &&
			node_color(sibling(n)->left) == RED &&
			node_color(sibling(n)->right) == BLACK)
	{
		sibling(n)->color = RED;
		sibling(n)->left->color = BLACK;
		rotate_right(t, sibling(n));
	} else if (n == n->parent->right &&
			node_color(sibling(n)) == BLACK &&
			node_color(sibling(n)->right) == RED &&
			node_color(sibling(n)->left) == BLACK)
	{
		sibling(n)->color = RED;
		sibling(n)->right->color = BLACK;
		rotate_left(t, sibling(n));
	}
	delete_6(t, n);
}

static void delete_6(struct rbtree* t, struct rbtree_node* n)
{
	sibling(n)->color = node_color(n->parent);
	n->parent->color = BLACK;

	if (n == n->parent->left) {
		assert (node_color(sibling(n)->right) == RED);
		sibling(n)->right->color = BLACK;
		rotate_left(t, n->parent);
	} else {
		assert (node_color(sibling(n)->left) == RED);
		sibling(n)->left->color = BLACK;
		rotate_right(t, n->parent);
	}
}

static void insert_1(struct rbtree* t, struct rbtree_node* n)
{
	if (n->parent == NULL)
		n->color = BLACK;
	else
		insert_2(t, n);
}

static void insert_2(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(n->parent) == BLACK)
		return;
	else
		insert_3(t, n);
}

static void insert_3(struct rbtree* t, struct rbtree_node* n)
{
	if (node_color(uncle(n)) == RED) {
		n->parent->color = BLACK;
		uncle(n)->color = BLACK;
		grandparent(n)->color = RED;
		insert_1(t, grandparent(n));
	} else {
		insert_4(t, n);
	}
}

static void insert_4(struct rbtree* t, struct rbtree_node* n)
{
	if (n == n->parent->right && n->parent == grandparent(n)->left) {
		rotate_left(t, n->parent);
		n = n->left;
	} else if (n == n->parent->left && n->parent == grandparent(n)->right) {
		rotate_right(t, n->parent);
		n = n->right;
	}
	insert_5(t, n);
}

static void insert_5(struct rbtree* t, struct rbtree_node* n)
{
	n->parent->color = BLACK;
	grandparent(n)->color = RED;
	if (n == n->parent->left && n->parent == grandparent(n)->left) {
		rotate_right(t, grandparent(n));
	} else {
		assert (n == n->parent->right && n->parent == grandparent(n)->right);
		rotate_left(t, grandparent(n));
	}
}


static struct rbtree_node* sibling(struct rbtree_node* n)
{
	assert(n != NULL);
	assert(n->parent != NULL);

	if (n == n->parent->left)
		return n->parent->right;
	else
		return n->parent->left;
}

static struct rbtree_node* uncle(struct rbtree_node* n)
{
	assert(n != NULL);
	assert(n->parent != NULL);
	assert(n->parent->parent != NULL);

	return sibling(n->parent);
}

static enum rbtree_color node_color(struct rbtree_node* n)
{
	return n == NULL ? BLACK : n->color;
}

struct rbtree *rbtree_init(int (*compare)(void *, void *))
{
	struct rbtree *tree;

	tree = malloc(sizeof(*tree));
	if (tree == NULL)
		return NULL;

	memset(tree, 0, sizeof(*tree));

	tree->root    = NULL;
	tree->size    = 0;

	tree->compare = compare;

	return tree;
}

struct rbtree_node *rbtree_lookup(struct rbtree* t, void* key) {

	struct rbtree_node* n = t->root;

	while (n != NULL) {
		int comp_result = t->compare(key, n->key);
		if (comp_result == 0) {
			return n;
		} else if (comp_result < 0) {
			n = n->left;
		} else {
			assert(comp_result > 0);
			n = n->right;
		}
	}
	return n;
}

void rotate_left(struct rbtree* t, struct rbtree_node* n) {
	struct rbtree_node* r = n->right;
	replace_node(t, n, r);
	n->right = r->left;
	if (r->left != NULL) {
		r->left->parent = n;
	}
	r->left = n;
	n->parent = r;
}

void rotate_right(struct rbtree* t, struct rbtree_node* n) {

	struct rbtree_node* L = n->left;

	replace_node(t, n, L);
	n->left = L->right;
	if (L->right != NULL) {
		L->right->parent = n;
	}
	L->right = n;
	n->parent = L;
}

void replace_node(struct rbtree* t, struct rbtree_node* oldn,
		struct rbtree_node* newn)
{
	if (oldn->parent == NULL) {
		t->root = newn;
	} else {
		if (oldn == oldn->parent->left)
			oldn->parent->left = newn;
		else
			oldn->parent->right = newn;
	}
	if (newn != NULL) {
		newn->parent = oldn->parent;
	}
}

struct rbtree_node *rbtree_insert(struct rbtree* t, void *key, void *data)
{
	struct rbtree_node *n, *new_node;

	new_node = malloc(sizeof(*new_node));
	if (new_node == NULL)
		return NULL;

	memset(new_node, 0, sizeof(*new_node));

	new_node->key  = key;
	new_node->data = data;

	new_node->color  = RED;
	new_node->left   = NULL;
	new_node->right  = NULL;
	new_node->parent = NULL;

	if (t->root == NULL) {
		t->root = new_node;
		goto out;
	}

	n = t->root;

	while (1) {
		int comp_result = t->compare(new_node->key, n->key);
		if (comp_result == 0) {
			goto err;
		} else if (comp_result < 0) {
			if (n->left == NULL) {
				n->left = new_node;
				break;
			} else {
				n = n->left;
			}
		} else {
			assert (comp_result > 0);
			if (n->right == NULL) {
				n->right = new_node;
				break;
			} else {
				n = n->right;
			}
		}
	}
	new_node->parent = n;

out:
	t->size++;
	insert_1(t, new_node);

	return new_node;

err:
	free(new_node);
	return NULL;
}

struct rbtree_node *rbtree_delete_by_node(struct rbtree* t, struct rbtree_node *n)
{
	struct rbtree_node* child;

	assert(t);
	assert(n);

	if (n->left != NULL && n->right != NULL) {
		/* Copy key/data from predecessor and then delete it instead */
		struct rbtree_node* pred = rbtree_lookup_max_node(n->left);
		n->key = pred->key;
		n->data = pred->data;
		n = pred;
	}

	assert(n->left == NULL || n->right == NULL);

	child = n->right == NULL ? n->left : n->right;
	if (node_color(n) == BLACK) {
		n->color = node_color(child);
		delete_1(t, n);
	}
	replace_node(t, n, child);

	t->size--;

	return n;
}

struct rbtree_node *rbtree_delete(struct rbtree* t, void* key)
{
	struct rbtree_node *n;

	n = rbtree_lookup(t, key);
	if (n == NULL)
		return NULL;

	return rbtree_delete_by_node(t, n);
}


struct rbtree_node *rbtree_lookup_max_node(struct rbtree_node* n)
{
	if (n == NULL)
		return NULL;

	while (n->right != NULL)
		n = n->right;

	return n;
}

struct rbtree_node *rbtree_lookup_min_node(struct rbtree_node* n)
{
	if (n == NULL)
		return NULL;

	while (n->left != NULL)
		n = n->left;

	return n;
}

size_t rbtree_size(struct rbtree *tree)
{
	return tree->size;
}

struct rbtree_node *rbtree_node_alloc(void)
{
	return malloc(sizeof(struct rbtree_node));
}

void rbtree_node_free(struct rbtree_node *n)
{
	free(n);
}

void rbtree_rbtree_free(struct rbtree *tree)
{
	free(tree);
}

/* Argument is the "key" element */
static int cmp_timespec(void *left, void *right)
{
	struct timespec *l, *r;

	l = (struct timespec *)left;
	r = (struct timespec *)right;

	if (l->tv_sec < r->tv_sec) {
		return -1;
	}
	else if (l->tv_sec > r->tv_sec) {
		return 1;
	}
	else { /* seconds identical */
		if (l->tv_nsec < r->tv_nsec) {
			return -1;
		}
		else if (l->tv_nsec > r->tv_nsec) {
			return 1;
		}
		else { /* seconds AND nanoseconds identical, uniqueness via pointer value */
			if (left < right)
				return -1;
			else if (left > right)
				return 1;
			else /* Failure: duplicate */
				return 0;
		}
	}
}

struct ev_data_select {
	struct rbtree *tree;
};

static struct ev *ev_new_select(void)
{
	struct ev *ev;
	struct ev_data_select *ev_priv_data;

	ev = struct_ev_new_internal();
	if (!ev)
		return NULL;

	ev_priv_data = malloc(sizeof(*ev_priv_data));
	if (!ev_priv_data)
		return NULL;

	memset(ev_priv_data, 0, sizeof(*ev_priv_data));
	ev->priv_data = ev_priv_data;

	ev_priv_data->tree = rbtree_init(cmp_timespec);
	if (!ev_priv_data->tree)
		return NULL;

	ev->size        = 0;
	ev->break_loop  = 0;

	return ev;
}

static void ev_free_select(struct ev *ev)
{
	struct ev_data_select *ev_priv_data;

	assert(ev);
	assert(ev->priv_data);

	ev_priv_data = ev->priv_data;

	assert(ev_priv_data->tree);

	rbtree_rbtree_free(ev_priv_data->tree);
	free(ev->priv_data);
	free(ev);

	ev = NULL;
}

static struct ev_entry *ev_entry_new_select_internal(void)
{
	struct ev_entry *ev_entry;

	ev_entry = malloc(sizeof(struct ev_entry));
	if (!ev_entry)
		return NULL;

	memset(ev_entry, 0, sizeof(struct ev_entry));

	ev_entry->priv_data = malloc(sizeof(struct ev_entry_data_select));
	if (!ev_entry->priv_data) {
		free(ev_entry);
		return NULL;
	}

	memset(ev_entry->priv_data, 0, sizeof(struct ev_entry_data_select));

	return ev_entry;
}

static struct ev_entry *ev_entry_new_select(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	(void) fd;
	(void) what;
	(void) cb;
	(void) data;

	return NULL;
}

static struct ev_entry *ev_timer_new_select(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	struct ev_entry *ev_entry;

	assert(timespec);
	assert(cb);

	ev_entry = ev_entry_new_select_internal();
	if (!ev_entry)
		return NULL;

	ev_entry->type     = EV_TIMEOUT;
	ev_entry->timer_cb = cb;
	ev_entry->data     = data;

	memcpy(&ev_entry->timespec, timespec, sizeof(*timespec));

	return ev_entry;
}

static void ev_entry_free_select(struct ev_entry *ev_entry)
{
	assert(ev_entry);
	assert(ev_entry->priv_data);

	free(ev_entry->priv_data);
	free(ev_entry);
}

static int ev_free_event_select(struct ev *ev, struct rbtree_node *node)
{
	struct ev_data_select *ev_data_select;
	struct ev_entry_data_select *ev_entry_data_select;
	struct ev_entry *ev_entry;

	assert(ev);
	assert(ev->priv_data);
	assert(node);
	assert(node->data);

	ev_entry = node->data;
	ev_entry_data_select = ev_entry->priv_data;

	assert(ev_entry_data_select);

	ev_data_select = ev->priv_data;

	/* remove from rbtree */
	node = rbtree_delete_by_node(ev_data_select->tree, node);
	if (!node) {
		pr_debug("Failure in deleting node from rbtree\n");
		return EV_FAILURE;
	}

	/* free rbtree_node memory */
	rbtree_node_free(node);

	/* free ev_entry data */
	ev_entry_free(ev_entry);

	return EV_SUCCESS;
}

static int ev_timer_cancel_select(struct ev *ev, struct ev_entry *ev_entry)
{
	struct ev_entry_data_select *ev_entry_data_select;

	ev_entry_data_select = ev_entry->priv_data;

	return ev_free_event_select(ev, ev_entry_data_select->node);
}

/* insert timer into rbtree */
static int ev_select_arm_timer(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;
	struct rbtree_node *node;
	struct ev_entry_data_select *ev_entry_data_select;
	struct ev_data_select *ev_priv_data;
	struct timespec now;

	assert(ev);
	assert(ev->priv_data);
	assert(ev_entry);
	assert(ev_entry->priv_data);

	ev_entry_data_select = ev_entry->priv_data;

	ev_priv_data = ev->priv_data;

	/* ok, it is time to convert the offset into a absolute time */
	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (ret < 0) {
		return EV_FAILURE;
	}

	timespec_add(&ev_entry->timespec, &ev_entry->timespec, &now);

	node = rbtree_insert(ev_priv_data->tree, (void *)&ev_entry->timespec, (void *)ev_entry);
	if (node == NULL) {
		return EV_FAILURE;
	}

	ev_entry_data_select->node = node;

	return EV_SUCCESS;
}

static int ev_add_select(struct ev *ev, struct ev_entry *ev_entry)
{
	int ret;

	switch (ev_entry->type) {
	case EV_TIMEOUT:
		ret = ev_select_arm_timer(ev, ev_entry);
		break;
	default:
		return EV_FAILURE;
	}

	if (ret != EV_SUCCESS)
		return ret;

	ev->size++;

	return EV_SUCCESS;
}

int ev_del_select(struct ev *ev, struct ev_entry *ev_entry)
{
	(void) ev;
	(void) ev_entry;

	assert(ev);
	assert(ev_entry);

	return EV_FAILURE;
}


int ev_loop_select(struct ev *ev, uint32_t flags)
{
	int ret;
	struct timespec now;
	struct rbtree_node *min_node;
	struct ev_data_select *ev_data_select;
	fd_set rfds;
	struct timeval tv;
	struct timespec timespec_res;
	struct ev_entry *ev_entry;

	/* not used yet and ignored */
	(void) flags;

	assert(ev);
	assert(ev->priv_data);

	ev_data_select = ev->priv_data;

	while (1) {

		ret = clock_gettime(CLOCK_REALTIME, &now);
		if (ret < 0) {
			return EV_FAILURE;
		}

		/* select next element from tree and arm select loop */
		min_node = rbtree_lookup_min_node(ev_data_select->tree->root);
		if (!min_node) {
			/* no timers in the queue anymore - exit loop */
			return EV_SUCCESS;
		}

		ev_entry = min_node->data;

		if (timespec_cmp(&now, &ev_entry->timespec, >)) {

			pr_debug("event %p executed\n", min_node);

			/* call user provided callback */
			ev_entry->timer_cb(ev_entry->data);

			ret = ev_free_event_select(ev, min_node);
			if (ret != EV_SUCCESS)
				return ret;

			continue;
		}

		/* ok, next timer is in the future, arm select() */

		FD_ZERO(&rfds);

		/* convert from absolut to offset */
		timespec_sub(&timespec_res, &ev_entry->timespec, &now);

		tv.tv_sec  = timespec_res.tv_sec;
		tv.tv_usec = timespec_res.tv_nsec / 1000;

		pr_debug("call select() with timeout %ld:%ld\n", tv.tv_sec, tv.tv_usec);

		ret = select(0, &rfds, NULL, NULL, &tv);
		if (ret == -1) {
			pr_debug("select(): %s", strerror(errno));
			return EV_FAILURE;
		}
		else if (ret)
			printf("Data is available now.\n");
			/* FD_ISSET(0, &rfds) will be true. */
		else {
			/* timer fired */
		}

	}
}

/* actual epoll/timer_fd API methods definitions is here */
struct ev *ev_new(void)
{
	return ev_new_select();
}

void ev_free(struct ev *ev)
{
	return ev_free_select(ev);
}

struct ev_entry *ev_entry_new(int fd, int what,
		void (*cb)(int, int, void *), void *data)
{
	return ev_entry_new_select(fd, what, cb, data);
}

struct ev_entry *ev_timer_new(struct timespec *timespec,
		void (*cb)(void *), void *data)
{
	return ev_timer_new_select(timespec, cb, data);
}

void ev_entry_free(struct ev_entry *ev_entry)
{
	ev_entry_free_select(ev_entry);
}

int ev_timer_cancel(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_timer_cancel_select(ev, ev_entry);
}

int ev_add(struct ev *ev, struct ev_entry *ev_entry) {
	return ev_add_select(ev, ev_entry);
}

int ev_del(struct ev *ev, struct ev_entry *ev_entry)
{
	return ev_del_select(ev, ev_entry);
}

int ev_loop(struct ev *ev, uint32_t flags)
{
	return ev_loop_select(ev, flags);
}


#else
# error "No event mechanism defined (epoll, select, ..) - "
        "adjust your Makefile and define -DHAVE_EPOLL, -DHAVE_SELECT or something"
#endif
