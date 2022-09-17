#include <assert.h>
#include <coro.h>

#include "test_harness.h"

static int is_ready(void *arg)
{
    return *(bool *)arg ? 0 : 1;
}

static void callback(void *arg)
{
    *(bool *)arg = true;
}

void *main_task(void *arg)
{
    bool b = false;

    coro_callsoon(NULL, callback, &b);
    coro_wait_custom(is_ready, &b);

    assert(b);

    *(int *)arg = 1;
    return arg;
}
