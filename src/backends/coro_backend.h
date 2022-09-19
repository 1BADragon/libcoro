#ifndef CORO_BACKEND_H
#define CORO_BACKEND_H

#include <stdint.h>
#include <coro.h>

// Forward declare
struct coro_backend;
struct coro_loop;
struct coro_trigger;

/// IO event callback from the backend, this is only used for IO triggers.
typedef void(*coro_io_triggered_f)(struct coro_trigger *, int revents);
/// Event callback for all other backend items.
typedef void(*coro_triggered_f)(struct coro_trigger *);

/**
 * @brief The coro_backend_type struct is used to define the API of a coroutine backend. The type
 * struct only stores functions pointers for desired functionality. Backend API gives backend
 * ability to create a custom context that will be passed in for a majority of the API functions.
 */
struct coro_backend_type {
    /// Creates a new backend context from this type. Currently flags is unused.
    struct coro_backend *(*backend_new)(int flags);
    /// Destroys a backend context.
    void (*backend_free)(struct coro_backend *);
    /// Starts the event loop of the backend context. This should be the entry and exit point for
    /// the backend event loop.
    void (*backend_start)(struct coro_backend *);
    /// Stops the event loop of the backend context. This should break all the way out of the
    /// backend loop.
    void (*backend_stop)(struct coro_backend *);

    /// Create a new io trigger context. Trigger function should be called with the event gathered.
    /// Trigger should be active when this function returns.
    void *(*new_io)(struct coro_backend *, coro_io_triggered_f, struct coro_trigger *,
                   int fd, int events);
    /// Deactivates and releases the io trigger from the caller.
    void (*free_io)(void *);

    /// New idle watcher, should be called when no other watchers are triggered. Should be active
    /// when this function returns.
    void *(*new_idle)(struct coro_backend *, coro_triggered_f, struct coro_trigger *);
    // Deactivates and releases the idle trigger from the caller
    void (*free_idle)(void *);

    /// New async watcher, triggered manually by *trigger_async* API function. Should be active
    /// when this function returns.
    void *(*new_async)(struct coro_backend *, coro_triggered_f, struct coro_trigger *);
    /// Deactivates and releases the async trigger from the caller
    void (*free_async)(void *);
    /// Triggers and async trigger. Should be thread-safe if backend supports multi-threading.
    void (*trigger_async)(void *);

    /// New timer. Should be active when returned.
    void *(*new_timer)(struct coro_backend *, coro_triggered_f, struct coro_trigger *,
                       uintmax_t time_ms);
    /// Deactivates and releases timer from the caller.
    void (*free_timer)(void *);
};

/**
 * @brief Selects and returns a coroutine backend based on given flags.
 * @param flags One of CORO_BACKEND_* used to select backend.
 * @return Either a valid backend or NULL if one could not be selected.
 */
struct coro_backend_type *coro_select_backend(int flags);

#endif //CORO_BACKEND_H
