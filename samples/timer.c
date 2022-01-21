#include <stdio.h>
#include <coro.h>

coro static void *task1(void *data)
{
    (void)data;

    for (size_t i = 0; i < 5; ++i) {
        coro_sleep(1);
        printf("Hello from task %s\n", coro_task_name(coro_current_task()));
    }

    return NULL;
}

coro static void *task2(void *data)
{
    coro_sleepms(500);
    return task1(data);
}

int main()
{
    struct coro_loop *loop = coro_new_loop(0);

    struct coro_task *t1 = coro_create_task(loop, &task1, NULL);
    struct coro_task *t2 = coro_create_task(loop, &task2, NULL);

    coro_task_set_name(t1, "t1");
    coro_task_set_name(t2, "t2");

    coro_run(loop);
    coro_task_join(t1);
    coro_task_join(t2);

    coro_free_loop(loop);
    return 0;
}
