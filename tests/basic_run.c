#include <assert.h>
#include <coro.h>
#include "test_harness.h"

void *main_task(void *arg)
{
    int *a = arg;

    *a = 1;

    return a;
}
