#ifndef CORO_BACKEND_H
#define CORO_BACKEND_H

#include <stdint.h>
#include <coro.h>

// Forward declare
struct coro_backend;
struct coro_loop;
struct coro_trigger;

typedef void(*coro_io_triggered_f)(struct coro_trigger *, int revents);
typedef void(*coro_triggered_f)(struct coro_trigger *);
typedef void(*coro_maintenance_f)(struct coro_loop *);

struct coro_backend_type {
    struct coro_backend *(*backend_new)(int flags);
    void (*backend_free)(struct coro_backend *);
    void (*backend_start)(struct coro_backend *);
    void (*backend_stop)(struct coro_backend *);
    void (*register_maintenance)(struct coro_backend *,
                                 struct coro_loop *,
                                 coro_maintenance_f func);

    void *(*new_io)(struct coro_backend *, coro_io_triggered_f, struct coro_trigger *,
                   int fd, int events);
    void (*free_io)(void *);

    void *(*new_idle)(struct coro_backend *, coro_triggered_f, struct coro_trigger *);
    void (*free_idle)(void *);

    void *(*new_async)(struct coro_backend *, coro_triggered_f, struct coro_trigger *);
    void (*free_async)(void *);
    void (*trigger_async)(void *);

    void *(*new_timer)(struct coro_backend *, coro_triggered_f, struct coro_trigger *,
                       uintmax_t time_ms);
    void (*free_timer)(void *);
};

struct coro_backend_type *coro_select_backend(int flags);

#endif //CORO_BACKEND_H
