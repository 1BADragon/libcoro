#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <coro.h>


void *timer_entry(void *arg)
{
    (void)arg;
    time_t start_time = time(NULL);

    coro_sleep(2);

    time_t end_time = time(NULL);
    assert(end_time - start_time >= 2);
    assert(end_time - start_time < 3);

    return NULL;
}

int main()
{
    struct coro_loop *loop = coro_new_loop(0);

    coro_create_task(loop, &timer_entry, NULL);
    coro_run(loop);
    coro_free_loop(loop);

    return 0;
}
