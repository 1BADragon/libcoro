#include <stdio.h>
#include <coro.h>

coro static void *hello_world(void *arg)
{
    (void) arg;

    coro_yeild();
    printf("Hello, World!\n");

    return NULL;
}

int main()
{
    int rc;
    struct coro_loop *loop;
    struct coro_task *task;

    loop = coro_new_loop(0);

    if (!loop) {
        return -1;
    }

    task = coro_create_task(loop, hello_world, NULL);
    rc = coro_run(loop);

    coro_task_join(task);
    coro_free_loop(loop);
    return rc;
}
