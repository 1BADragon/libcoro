#include <stdlib.h>

#include <task.h>

struct coro_task *task_new(size_t stack_size)
{
    struct coro_task *task = NULL;

    task = calloc(1, sizeof(struct coro_task));
    if (!task) {
        goto error;
    }

    task->stack = calloc(stack_size, sizeof(char));
    if (!task->stack) {
        goto error;
    }
    task->stack_size = stack_size;

    task->state = TASK_STATE_INIT;

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

    if (task->stack) {
        free(task->stack);
    }

    free(task);
}
