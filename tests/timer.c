#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <coro.h>

#include "test_harness.h"

void *main_task(void *arg)
{
    (void)arg;
    time_t start_time = time(NULL);

    coro_sleep(2);

    time_t end_time = time(NULL);
    assert(end_time - start_time >= 2);
    assert(end_time - start_time < 3);

    *(int *)arg = 1;
    return arg;
}
