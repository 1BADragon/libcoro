#include <coro.h>

#include "test_harness.h"

#define N_TASKS (1000)

void *task_entry(void *arg)
{
    int *i = arg;
    *i = 1;
    return i;
}

void *main_task(void *arg)
{
    int *i = arg;
    struct coro_task *tasks[N_TASKS];

    for (size_t i = 0; i < N_TASKS; ++i) {
        int *t_arg = coro_zalloc(sizeof(int));
        assert(t_arg);
        tasks[i] = coro_create_task(NULL, task_entry, t_arg);
        assert(tasks[i]);
    }

    coro_wait_tasks(tasks, N_TASKS, CORO_TASK_WAIT_ALL);

    for (size_t i = 0; i < N_TASKS; ++i) {
        int *ret = coro_task_join(tasks[i]);

        assert(*ret);
        coro_free(ret);
    }

    *i = 1;
    return i;
}
