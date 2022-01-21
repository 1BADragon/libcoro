#include <assert.h>
#include <coro.h>


static void *task_entry(void *arg)
{
    int *a = arg;

    *a = 1;

    return a;
}

int main()
{
    int arg = 0;
    struct coro_loop *loop = coro_new_loop(0);

    struct coro_task *task = coro_create_task(loop, task_entry, &arg);
    coro_run(loop);

    int *ret = coro_task_join(task);

    assert(ret == &arg);
    assert(arg == 1);

    coro_free_loop(loop);

    return 0;
}
