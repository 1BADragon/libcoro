#ifndef CORO_SCHEDULER_H
#define CORO_SCHEDULER_H

#include <coro.h>
#include <coro_ev.h>

struct coro_scheduler;

struct coro_scheduler *coro_scheduler_new();
void coro_scheduler_free(struct coro_scheduler *s);

void coro_sched_set_loop(struct coro_scheduler *s,
                         struct coro_loop *l);

struct coro_loop *coro_sched_loop(struct coro_scheduler *s);
struct coro_task *coro_sched_active(struct coro_scheduler *s);

#endif // CORO_SCHEDULER_H
