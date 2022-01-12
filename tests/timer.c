#include <stdio.h>
#include <coro.h>

static void *task(void *data)
{
    (void)data;

    for (size_t i = 0; i < 5; ++i) {
        coro_sleep(1);
        printf("Hello from task %p\n", coro_current_task());
    }

    return NULL;
}

int main() {
    struct coro_loop *loop = coro_new_loop(0);

    struct coro_task *t1 = coro_create_task(loop, &task, NULL);
    struct coro_task *t2 = coro_create_task(loop, &task, NULL);

    coro_run(loop);
    coro_task_join(t1);
    coro_task_join(t2);

    coro_free_loop(loop);
    return 0;
}
