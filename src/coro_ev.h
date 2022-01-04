#ifndef CORO_EV_H
#define CORO_EV_H

struct coro_task;
int coro_event_trigger(struct coro_task *t, int revent);

#define EV_CB_DECLARE(type)   struct coro_task *cb;
#define EV_CB_INVOKE(watcher, revents) coro_event_trigger ((watcher)->cb, revents)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"

#include <deps/libev/ev.h>


#endif // CORO_EV_H
