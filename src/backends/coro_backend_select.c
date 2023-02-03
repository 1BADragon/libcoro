#include <stdbool.h>
#include <sys/select.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <assert.h>

#include <backends/coro_backend_ev.h>
#include <macro.h>
#include <tree.h>

enum watcher_type {
    WATCHER_IO,
    WATCHER_ASYNC,
    WATCHER_TIMER,
};

struct coro_select_watcher;
static int watcher_cmp(struct coro_select_watcher *a,
                       struct coro_select_watcher *b);

struct coro_select_watcher {
    RB_ENTRY(coro_select_watcher) node;

    int fd;

    int events;
    struct coro_backend *backend;
    struct coro_trigger *trigger;
    enum watcher_type type;

    union {
        coro_io_triggered_f io_cb;
        coro_triggered_f cb;
    };
};

RB_HEAD(watchers, coro_select_watcher);
RB_PROTOTYPE_STATIC(watchers, coro_select_watcher, node, watcher_cmp);

struct coro_backend {
    struct watchers watchers;
    bool should_run;
};

static struct coro_backend *coro_select_new(int flags);
static void coro_select_free(struct coro_backend *backend);
static void coro_select_start(struct coro_backend *backend);
static void coro_select_stop(struct coro_backend *backend);
static void *coro_select_new_io(struct coro_backend *backend,
                               coro_io_triggered_f func,
                               struct coro_trigger *trigger,
                               int fd, int events);
static void coro_select_free_io(void *_io);
static void *coro_select_new_async(struct coro_backend *backend,
                                  coro_triggered_f func,
                                  struct coro_trigger *trigger);
static void coro_select_free_async(void *_async);
static void coro_select_trigger_async(void *_async);
static void *coro_select_new_timer(struct coro_backend *backend,
                                  coro_triggered_f func,
                                  struct coro_trigger *trigger,
                                  uintmax_t time_ms);
static void coro_select_free_timer(void *_timer);

static struct coro_backend_type coro_select_backend_type = {
    .backend_new = coro_select_new,
    .backend_free = coro_select_free,
    .backend_start = coro_select_start,
    .backend_stop = coro_select_stop,

    .new_io = coro_select_new_io,
    .free_io = coro_select_free_io,

    .new_async = coro_select_new_async,
    .free_async = coro_select_free_async,
    .trigger_async = coro_select_trigger_async,

    .new_timer = coro_select_new_timer,
    .free_timer = coro_select_free_timer
};

struct coro_backend_type *coro_select_backend(void)
{
    return &coro_select_backend_type;
}

static struct coro_backend *coro_select_new(int flags)
{
    (void) flags;
    struct coro_backend *new = coro_zalloc(sizeof(struct coro_backend));

    if (NULL == new) {
        return NULL;
    }

    RB_INIT(&new->watchers);

    return new;
}

static void coro_select_free(struct coro_backend *backend)
{
    coro_free(backend);
}

static int watcher_cmp(struct coro_select_watcher *a,
                       struct coro_select_watcher *b)
{
    return a->fd - b->fd;
}

static void coro_select_start(struct coro_backend *backend)
{
    fd_set rds;
    fd_set wts;
    uint64_t val8;
    int revents;
    int maxfd;
    struct coro_select_watcher key;
    struct coro_select_watcher *at;

    backend->should_run = true;

    while(backend->should_run) {
        FD_ZERO(&rds);
        FD_ZERO(&wts);
        maxfd = -1;

        RB_FOREACH(at, watchers, &backend->watchers) {
            if (at->events & CORO_FD_WAIT_READ) {
                FD_SET(at->fd, &rds);

                if (at->fd > maxfd) {
                    maxfd = at->fd;
                }
            }

            if (at->events & CORO_FD_WAIT_WRITE) {
                FD_SET(at->fd, &wts);

                if (at->fd > maxfd) {
                    maxfd = at->fd;
                }
            }
        }

        int rc = select(maxfd + 1, &rds, &wts, NULL, NULL);

        if (rc == -1) {
            return;
        }

        for (int fdat = 0; fdat < maxfd+1; fdat++) {
            revents = 0;
            if (FD_ISSET(fdat, &rds)) {
                revents |= CORO_FD_WAIT_READ;
            }

            if (FD_ISSET(fdat, &wts)) {
                revents |= CORO_FD_WAIT_WRITE;
            }

            if (0 == revents) {
                continue;
            }

            key.fd = fdat;
            at = watchers_RB_FIND(&backend->watchers, &key);

            if (NULL == at) {
                continue;
            }

            printf("Watcher %p of type %d triggered\n", at, at->type);

            switch (at->type) {
            case WATCHER_IO:
                at->io_cb(at->trigger, revents);
                break;
            case WATCHER_ASYNC:
                read(at->fd, &val8, sizeof(uint64_t));
                if (val8 != 0) {
                    at->cb(at->trigger);
                }
                break;
            case WATCHER_TIMER:
                read(at->fd, &val8, sizeof(uint64_t));
                if (val8 != 0) {
                    at->cb(at->trigger);
                }
                break;
            default:
                assert(0);
            }
        }
    }
}

static void coro_select_stop(struct coro_backend *backend)
{
    backend->should_run = false;
}

static void *coro_select_new_io(struct coro_backend *backend,
                               coro_io_triggered_f func,
                               struct coro_trigger *trigger,
                               int fd, int events)
{
    struct coro_select_watcher key;
    struct coro_select_watcher *new;

    key.fd = fd;
    if (watchers_RB_FIND(&backend->watchers, &key)) {
        assert(0);
        return NULL;
    }

    new = coro_zalloc(sizeof(struct coro_select_watcher));
    if (NULL == new) {
        return NULL;
    }

    new->backend = backend;
    new->io_cb = func;
    new->trigger = trigger;
    new->fd = fd;
    new->events = events;
    new->type = WATCHER_IO;

    watchers_RB_INSERT(&backend->watchers, new);
    return new;
}

static void coro_select_free_io(void *_io)
{
    struct coro_select_watcher *w = (struct coro_select_watcher *)_io;

    watchers_RB_REMOVE(&w->backend->watchers, w);
    coro_free(w);
}

static void *coro_select_new_async(struct coro_backend *backend,
                                  coro_triggered_f func,
                                  struct coro_trigger *trigger)
{
    struct coro_select_watcher *new;

    new = coro_zalloc(sizeof(struct coro_select_watcher));
    if (NULL == new) {
        return NULL;
    }

    new->backend = backend;
    new->cb = func;
    new->trigger = trigger;
    new->fd = eventfd(0, EFD_CLOEXEC);
    new->events = CORO_FD_WAIT_READ;
    new->type = WATCHER_ASYNC;

    if (-1 == new->fd) {
        coro_free(new);
        return NULL;
    }

    watchers_RB_INSERT(&backend->watchers, new);
    return new;
}

static void coro_select_free_async(void *_async)
{
    struct coro_select_watcher *w = (struct coro_select_watcher *)_async;

    watchers_RB_REMOVE(&w->backend->watchers, w);
    close(w->fd);
    coro_free(w);
}

static void coro_select_trigger_async(void *_async)
{
    struct coro_select_watcher *w = (struct coro_select_watcher *)_async;

    uint64_t val = 1;

    write(w->fd, &val, sizeof(uint64_t));
}

static void *coro_select_new_timer(struct coro_backend *backend,
                                  coro_triggered_f func,
                                  struct coro_trigger *trigger,
                                  uintmax_t time_ms)
{
    struct itimerspec timer = {0};
    struct coro_select_watcher *new;

    new = coro_zalloc(sizeof(struct coro_select_watcher));
    if (NULL == new) {
        return NULL;
    }

    new->backend = backend;
    new->events = CORO_FD_WAIT_READ;
    new->cb = func;
    new->trigger = trigger;
    new->type = WATCHER_TIMER;

    new->fd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
    if (-1 == new->fd) {
        coro_free(new);
        return NULL;
    }

    timer.it_value.tv_sec = time_ms / 1000;
    timer.it_value.tv_nsec = (time_ms * 1000000) % 1000000;
    timerfd_settime(new->fd, 0, &timer, NULL);

    watchers_RB_INSERT(&backend->watchers, new);
    return new;
}

static void coro_select_free_timer(void *_timer)
{
    struct coro_select_watcher *w = (struct coro_select_watcher *)_timer;

    watchers_RB_REMOVE(&w->backend->watchers, w);
    close(w->fd);
    coro_free(w);
}

RB_GENERATE_STATIC(watchers, coro_select_watcher, node, watcher_cmp);
