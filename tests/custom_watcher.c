#include <stdbool.h>
#include <coro.h>

#include "test_harness.h"

static void *sleeper_task(void *raw_arg) {
    bool *arg = raw_arg;

    coro_sleepms(100);
    *arg = true;
    return NULL;
}

struct cb_data {
    bool called;
    bool *arg;
};

static int check_ready(void *cb_data)
{
    struct cb_data *arg = cb_data;
    arg->called = true;

    return (*arg->arg) ? 0 : 1;
}

static void *waiter_task(void *raw_arg)
{
    struct cb_data cb_data = {
        .called = false,
        .arg = raw_arg,
    };

    assert(!*cb_data.arg);
    coro_wait_custom(check_ready, &cb_data);
    assert(cb_data.called);
    assert(*cb_data.arg);

    return NULL;
}

void *main_task(void *arg)
{
    bool ready = false;
    struct coro_task *sleeper = NULL;
    struct coro_task *waiter = NULL;
    struct coro_task *tasks[2];

    sleeper = coro_create_task(NULL, sleeper_task, &ready);
    assert(sleeper != NULL);

    waiter = coro_create_task(NULL, waiter_task, &ready);
    assert(waiter != NULL);

    tasks[0] = sleeper;
    tasks[1] = waiter;
    coro_wait_tasks(tasks, 2, CORO_TASK_WAIT_ALL);

    assert(ready);

    *(int *)arg = 1;
    return arg;
}
