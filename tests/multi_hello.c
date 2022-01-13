#include <stdio.h>
#include <coro.h>

#define N 5

coro static void *print_val(void *arg)
{
    int t = *((int *)arg);

    if (t % 2) {
        coro_yeild();
    }

    printf("Hello %d\n", t);

    return NULL;
}

coro static void *print_hello(void *arg)
{
    (void)arg;

    printf("Hello, World\n");

    return NULL;
}

coro static void *multi_entry(void *arg)
{
    (void) arg;
    struct coro_task *tasks[N] = {NULL};
    int vals[N];

    coro_await(coro_create_task(NULL, print_hello, NULL));

    for (int i = 0; i < N; ++i) {
        vals[i] = i;
        tasks[i] = coro_create_task(NULL, print_val, &vals[i]);
    }

    coro_wait_tasks(tasks, N, CORO_TASK_WAIT_ALL);

    for (int i = 0; i < N; ++i) {
        coro_task_join(tasks[i]);
    }

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

    task = coro_create_task(loop, multi_entry, NULL);
    rc = coro_run(loop);

    coro_task_join(task);
    coro_free_loop(loop);
    return rc;
}
