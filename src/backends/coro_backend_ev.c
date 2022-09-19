#include <assert.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#include <ev.h>
#pragma GCC diagnostic pop

#include <backends/coro_backend_ev.h>

struct coro_ev_watcher {
    union ev_any_watcher watcher;
    struct coro_backend *backend;
    struct coro_trigger *trigger;
    void* cb;
};

struct coro_backend {
    struct ev_loop *_loop;
    struct coro_loop *parent;
};

static struct coro_backend *coro_libev_new(int flags);
static void coro_libev_free(struct coro_backend *backend);
static void coro_libev_start(struct coro_backend *backend);
static void coro_libev_stop(struct coro_backend *backend);
static void *coro_libev_new_io(struct coro_backend *backend,
                               coro_io_triggered_f func,
                               struct coro_trigger *trigger,
                               int fd, int events);
static void coro_libev_free_io(void *_io);
static void *coro_libev_new_idle(struct coro_backend *backend,
                                 coro_triggered_f func,
                                 struct coro_trigger *trigger);
static void coro_libev_free_idle(void *_idle);
static void *coro_libev_new_async(struct coro_backend *backend,
                                  coro_triggered_f func,
                                  struct coro_trigger *trigger);
static void coro_libev_free_async(void *_async);
static void coro_libev_trigger_async(void *_async);
static void *coro_libev_new_timer(struct coro_backend *backend,
                                  coro_triggered_f func,
                                  struct coro_trigger *trigger,
                                  uintmax_t time_ms);
static void coro_libev_free_timer(void *_timer);

static struct coro_ev_watcher *create_watcher(struct coro_backend *backend,
                                              void *cb,
                                              struct coro_trigger *trigger);
static void destroy_watcher(struct coro_ev_watcher *w);

static void coro_ev_io_cb(struct ev_loop *loop, ev_io *watcher, int revents);
static void coro_ev_idle_cb(struct ev_loop *loop, ev_idle *watcher, int revents);
static void coro_ev_async_cb(struct ev_loop *loop, ev_async *watcher, int revents);
static void coro_ev_timer_cb(struct ev_loop *loop, ev_timer *watcher, int revents);

static struct coro_backend_type coro_libev_backend_type = {
    .backend_new = coro_libev_new,
    .backend_free = coro_libev_free,
    .backend_start = coro_libev_start,
    .backend_stop = coro_libev_stop,

    .new_io = coro_libev_new_io,
    .free_io = coro_libev_free_io,

    .new_idle = coro_libev_new_idle,
    .free_idle = coro_libev_free_idle,

    .new_async = coro_libev_new_async,
    .free_async = coro_libev_free_async,
    .trigger_async = coro_libev_trigger_async,

    .new_timer = coro_libev_new_timer,
    .free_timer = coro_libev_free_timer
};

struct coro_backend_type *coro_libev_backend(void)
{
    return &coro_libev_backend_type;
}

static struct coro_backend *coro_libev_new(int flags)
{
    ev_set_allocator(&coro_realloc);
    (void) flags;
    struct coro_backend *backend = coro_zalloc(sizeof(struct coro_backend));
    if (!backend) {
        return NULL;
    }

    backend->_loop = ev_loop_new(0);
    if (!backend->_loop) {
        coro_free(backend);
        return NULL;
    }

    return backend;
}

static void coro_libev_free(struct coro_backend *backend)
{
    ev_loop_destroy(backend->_loop);
    coro_free(backend);
}

static void coro_libev_start(struct coro_backend *backend)
{
    ev_run(backend->_loop, 0);
}

static void coro_libev_stop(struct coro_backend *backend)
{
    ev_break(backend->_loop, EVBREAK_ALL);
}

static void *coro_libev_new_io(struct coro_backend *backend,
                               coro_io_triggered_f func,
                               struct coro_trigger *trigger,
                               int fd, int events)
{
    struct coro_ev_watcher *w = create_watcher(backend, func, trigger);
    if (!w) {
        return NULL;
    }

    ev_io_init(&w->watcher.io, &coro_ev_io_cb, fd, events);
    ev_io_start(backend->_loop, &w->watcher.io);

    return w;
}

static void coro_libev_free_io(void *_io)
{
    struct coro_ev_watcher *io = _io;
    ev_io_stop(io->backend->_loop, &io->watcher.io);

    destroy_watcher(io);
}

static void *coro_libev_new_idle(struct coro_backend *backend,
                                 coro_triggered_f func,
                                 struct coro_trigger *trigger)
{
    struct coro_ev_watcher *w = create_watcher(backend, func, trigger);

    if (!w) {
        return NULL;
    }

    ev_idle_init(&w->watcher.idle, &coro_ev_idle_cb);
    ev_idle_start(backend->_loop, &w->watcher.idle);

    return w;
}

static void coro_libev_free_idle(void *_idle)
{
    struct coro_ev_watcher *idle = _idle;

    ev_idle_stop(idle->backend->_loop, &idle->watcher.idle);
    destroy_watcher(idle);
}

static void *coro_libev_new_async(struct coro_backend *backend,
                                  coro_triggered_f func,
                                  struct coro_trigger *trigger)
{
    struct coro_ev_watcher *w = create_watcher(backend, func, trigger);

    if (!w) {
        return NULL;
    }

    ev_async_init(&w->watcher.async, &coro_ev_async_cb);
    ev_async_start(backend->_loop, &w->watcher.async);
    return w;
}

static void coro_libev_free_async(void *_async)
{
    struct coro_ev_watcher *async = _async;

    ev_async_stop(async->backend->_loop, &async->watcher.async);
    destroy_watcher(async);
}

static void coro_libev_trigger_async(void *_async)
{
    struct coro_ev_watcher *async = _async;

    ev_async_send(async->backend->_loop, &async->watcher.async);
}

static void *coro_libev_new_timer(struct coro_backend *backend,
                                  coro_triggered_f func,
                                  struct coro_trigger *trigger,
                                  uintmax_t time_ms)
{
    struct coro_ev_watcher *w = create_watcher(backend, func, trigger);

    if (!w) {
        return NULL;
    }

    ev_timer_init(&w->watcher.timer, &coro_ev_timer_cb, (ev_tstamp)time_ms / 1000., 0.);
    ev_timer_start(backend->_loop, &w->watcher.timer);
    return w;
}

static void coro_libev_free_timer(void *_timer)
{
    struct coro_ev_watcher *timer = _timer;

    ev_timer_stop(timer->backend->_loop, &timer->watcher.timer);
    destroy_watcher(timer);
}

static struct coro_ev_watcher *create_watcher(struct coro_backend *backend,
                                              void *cb,
                                              struct coro_trigger *trigger)
{
    struct coro_ev_watcher *w = coro_zalloc(sizeof(struct coro_ev_watcher));
    if (!w) {
        return NULL;
    }

    w->backend = backend;
    w->cb = cb;
    w->trigger = trigger;

    return w;
}

static void destroy_watcher(struct coro_ev_watcher *w)
{
    coro_free(w);
}

static void coro_ev_io_cb(struct ev_loop *loop, ev_io *watcher, int revents)
{
    (void)loop;
    struct coro_ev_watcher *w = (struct coro_ev_watcher *)watcher;

    assert(w->backend->_loop == loop);
    assert(w->cb);

    ((coro_io_triggered_f)w->cb)(w->trigger, revents);
}

static void coro_ev_idle_cb(struct ev_loop *loop, ev_idle *watcher, int revents)
{
    (void)loop;
    (void)revents;
    struct coro_ev_watcher *w = (struct coro_ev_watcher *)watcher;

    assert(w->backend->_loop == loop);
    assert(w->cb);
    assert(revents == EV_IDLE);

    ((coro_triggered_f)w->cb)(w->trigger);
}

static void coro_ev_async_cb(struct ev_loop *loop, ev_async *watcher, int revents)
{
    (void)loop;
    (void)revents;
    struct coro_ev_watcher *w = (struct coro_ev_watcher *)watcher;

    assert(w->backend->_loop == loop);
    assert(w->cb);
    assert(revents == EV_ASYNC);

    ((coro_triggered_f)w->cb)(w->trigger);
}

static void coro_ev_timer_cb(struct ev_loop *loop, ev_timer *watcher, int revents)
{
    (void)loop;
    (void)revents;
    struct coro_ev_watcher *w = (struct coro_ev_watcher *)watcher;

    assert(w->backend->_loop == loop);
    assert(w->cb);
    assert(revents == EV_TIMER);

    ((coro_triggered_f)w->cb)(w->trigger);
}
