#include <backends/coro_backend.h>

#ifdef CORO_SELECT_BACKEND_ENABLED
#   include <backends/coro_backend_select.h>
#endif

#ifdef CORO_LIBEV_BACKEND_ENABLED
#   include <backends/coro_backend_ev.h>
#endif

struct coro_backend_type *coro_create_backend(int flags)
{
    struct coro_backend_type *(*default_backend)() = NULL;
    struct coro_backend_type *backend = NULL;

#ifdef CORO_SELECT_BACKEND_ENABLED
    if (!default_backend) {
        default_backend = coro_select_backend;
    }
    if (flags & CORO_BACKEND_SELECT && backend == NULL) {
        backend = coro_select_backend();
        goto exit;
    }
#endif

#ifdef CORO_LIBEV_BACKEND_ENABLED
    if (!default_backend) {
        default_backend = coro_libev_backend;
    }
    if (flags & CORO_BACKEND_EV && backend == NULL) {
        backend = coro_libev_backend();
        goto exit;
    }
#endif

    if (!backend) {
        backend = default_backend();
    }

exit:
    return backend;
}
