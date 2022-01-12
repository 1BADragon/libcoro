#ifndef CORO_EV_H
#define CORO_EV_H

struct coro_task;

void coro_ev_cb_invoke(void *watcher, int revents);

#define EV_CB_DECLARE(type)   struct coro_task *cb;
#define EV_CB_INVOKE(watcher, revents) coro_ev_cb_invoke (watcher, revents)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"

#include <deps/libev/ev.h>


#endif // CORO_EV_H
