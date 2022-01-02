#ifndef CORO_TASK_H
#define CORO_TASK_H

#include <stdint.h>
#include <setjmp.h>
#include <list.h>

#include <coro.h>
#include <coro_ctx.h>
#include <coro_arch.h>

struct coro_scheduler;

enum coro_task_state {
    TASK_STATE_INIT,
    TASK_STATE_RUNNING,
    TASK_STATE_FINISHED
};

struct coro_task {
    struct list_head node;

    struct coro_scheduler *sched;
    int last_revent;

    coro_task_entry_f entry;
    void *arg;
    void *ret;

    struct coro_ctx ctx;
    enum coro_task_state state;
    uint8_t *stack;
    size_t stack_size;
};

struct coro_task *task_new(size_t stack_size);
void task_free(struct coro_task *task);


#endif // CORO_TASK_H
