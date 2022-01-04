#include <stdlib.h>
#include <stdio.h>

#include <task.h>
#include <coro.h>
#include <coro_int.h>
#include <scheduler.h>

static int allocate_stack(struct coro_task *t, size_t size);

struct coro_task *task_new(size_t stack_size)
{
    struct coro_task *task = NULL;

    task = calloc(1, sizeof(struct coro_task));
    if (!task) {
        goto error;
    }

    if (allocate_stack(task, stack_size)) {
        goto error;
    }
    task->state = TASK_STATE_INIT;

    // Make sure this is NULL
    task->waiter = NULL;

    printf("%s: task: %p\n", __func__, task);

    return task;
error:
    task_free(task);
    return NULL;
}

void task_free(struct coro_task *task)
{
    if (!task) {
        return;
    }

    task_destroy_watcher(task);

    if (task->stack) {
        free(task->stack);
    }

    free(task);
}

void task_destroy_watcher(struct coro_task *t)
{
    struct ev_loop *loop;

    loop = coro_loop_backend(coro_sched_loop(t->sched));

    switch (t->watcher_type) {
    case CORO_NONE:
        break;
    case CORO_IO:
        ev_io_stop(loop, &t->ev_watcher.io);
        break;
    case CORO_IDLE:
        ev_idle_stop(loop, &t->ev_watcher.idle);
        break;
    case CORO_ASYNC:
        ev_async_stop(loop, &t->ev_watcher.async);
        break;
    }

    t->watcher_type = CORO_NONE;
    memset(&t->ev_watcher, 0, sizeof(t->ev_watcher));
}

static int allocate_stack(struct coro_task *t, size_t size)
{
    t->stack = calloc(size, sizeof(uint8_t));

    if (!t->stack) {
        return -1;
    }

    t->stack_size = size;
    t->stack_top =
            (uint8_t *)((
                (uintptr_t)t->stack + t->stack_size) & ~0xf
                        );
    return 0;
}
