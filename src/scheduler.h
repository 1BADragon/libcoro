#ifndef CORO_SCHEDULER_H
#define CORO_SCHEDULER_H

#include <coro.h>

int coro_event_trigger(struct coro_task *t, int revent);

#endif // CORO_SCHEDULER_H
