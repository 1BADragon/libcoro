#ifndef CORO_SELECT_H
#define CORO_SELECT_H

#include <backends/coro_backend.h>

/**
 * @brief Returns a pointer to the libev coro backend.
 */
struct coro_backend_type *coro_select_backend(void);

#endif // CORO_EV_H
