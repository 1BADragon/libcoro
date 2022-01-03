#ifndef CORO_INT_H
#define CORO_INT_H

#include <coro.h>
#include <coro_ev.h>

struct ev_loop *coro_loop_backend(struct coro_loop *l);

#endif // CORO_INT_H
