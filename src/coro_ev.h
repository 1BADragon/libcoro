#ifndef CORO_EV_H
#define CORO_EV_H

#include <scheduler.h>

#define EV_CB_DECLARE(type)   struct coro_task *cb;
#define EV_CB_INVOKE(watcher, revents) coro_event_trigger ((watcher)->cb, revents)
#include <deps/libev/ev.h>

#endif // CORO_EV_H
