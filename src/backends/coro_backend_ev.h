#ifndef CORO_EV_H
#define CORO_EV_H

#include <backends/coro_backend.h>

struct coro_backend_type *coro_libev_backend(void);

#endif // CORO_EV_H
