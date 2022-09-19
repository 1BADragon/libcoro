#include <stdbool.h>
#include <coro.h>

#include "test_harness.h"

static void set_int(enum coro_exit_how how, void *arg);
static void *cancelled_task(void *);
static void *finished_task(void *);

void *main_task(void *arg)
{
    int set;
    struct coro_task *task = NULL;

    set = 0;
    task = coro_create_task(NULL, cancelled_task, &set);

    coro_sleepms(10);
    coro_cancel_task(task);
    coro_sleepms(10);

    assert(set == 1);

    set = 0;
    task = coro_create_task(NULL, finished_task, &set);

    coro_await(task);
    assert(set == 1);

    *(int *)arg = 1;
    return arg;
}

static void set_int(enum coro_exit_how how, void *arg)
{
    (void) how;
    *(int *)arg = 1;
}

static void *cancelled_task(void *arg)
{
    coro_register_cleanup(NULL, &set_int, arg);

    while (1) {
        coro_yeild();
    }

    return NULL;
}

static void *finished_task(void *arg)
{
    coro_register_cleanup(NULL, &set_int, arg);

    return NULL;
}
