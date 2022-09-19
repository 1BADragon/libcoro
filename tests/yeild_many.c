#include <coro.h>
#include <inttypes.h>

#include "test_harness.h"

static coro void *generator_task(void *arg);

coro void *main_task(void *arg)
{
    void *val;
    uintptr_t expected = 0;
    struct coro_task *task;

    task = coro_create_task(NULL, generator_task, NULL);

    while (!coro_await_val(task, &val)) {
        assert(expected == (uintptr_t)val);

        expected++;
    }

    assert(expected == (uintptr_t)val);

    *(int *)arg = 1;
    return arg;
}

static coro void *generator_task(void *arg)
{
    uintptr_t i;

    for (i = 0; i < 100; ++i) {
        coro_yeild_val((void *)i);
    }

    return (void *)i;
}
