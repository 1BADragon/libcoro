#ifndef CORO_TASK_H
#define CORO_TASK_H

#include <stdint.h>
#include <setjmp.h>
#include <list.h>

#include <coro.h>
#include <coro_ev.h>
#include <coro_ctx.h>
#include <coro_arch.h>

struct coro_scheduler;

enum coro_task_state {
    TASK_STATE_INIT,
    TASK_STATE_RUNNING,
    TASK_STATE_FINISHED
};

enum coro_watcher_type {
    CORO_NONE,
    CORO_IO,
    CORO_IDLE,
};

union coro_watchers {
    ev_io io;
    ev_idle idle;
};

struct coro_task {
    struct coro_scheduler *sched;
    int last_revent;

    coro_task_entry_f entry;
    void *arg;
    void *ret;

    enum coro_watcher_type watcher_type;
    union coro_watchers ev_watcher;

    struct coro_ctx ctx;
    enum coro_task_state state;
    uint8_t *stack;
    uint8_t *stack_top;
    size_t stack_size;
};

struct coro_task *task_new(size_t stack_size);
void task_free(struct coro_task *task);

void task_destroy_watcher(struct coro_task *t);

#endif // CORO_TASK_H
