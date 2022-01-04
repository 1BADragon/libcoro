#include <stdio.h>
#include <coro.h>

#define N 5

coro static void *print_val(void *arg)
{
    printf("Hello %d\n", *((int *)arg));

    return NULL;
}

coro static void *multi_entry(void *arg)
{
    (void) arg;
    struct coro_task *tasks[N] = {NULL};
    int vals[N];

    for (int i = 0; i < N; ++i) {
        vals[i] = i;
        tasks[i] = coro_create_task(NULL, print_val, &vals[i]);
    }

    coro_await_many(tasks, N, CORO_WAIT_ALL);

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
