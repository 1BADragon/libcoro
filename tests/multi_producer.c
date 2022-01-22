#include <stdlib.h>
#include <assert.h>
#include <coro.h>

#define N_PRODS (1000u)
#define N_VALS_P_PROD (100u)

struct consumer_args {
    int *val;
    struct coro_queue *queue;
};

void *producer_task(void *arg)
{
    struct coro_queue *queue = arg;

    for (size_t i = 0; i < N_VALS_P_PROD; ++i) {
        int *val = malloc(sizeof(int));

        *val = i;
        // no free function so memory leaks can be detected
        coro_queue_push(queue, val, NULL);
    }

    return NULL;
}

void *consumer_task(void *_arg)
{
    struct consumer_args *args = _arg;

    for (;;) {
        int *val = coro_queue_pop(args->queue);

        if (!val) {
            break;
        }

        (*args->val)++;
        free(val);
    }

    return NULL;
}

void *startup_task(void *arg)
{
    int val = 0;
    struct consumer_args cons_arg;
    struct coro_queue *queue = coro_queue_new(NULL);
    assert(queue);

    struct coro_task *tasks[N_PRODS + 1] = {0};

    for (size_t i = 0; i < N_PRODS; ++i) {
        tasks[i] = coro_create_task(NULL, producer_task, queue);
        coro_yeild();
    }

    cons_arg.queue = queue;
    cons_arg.val = &val;
    tasks[N_PRODS] = coro_create_task(NULL, consumer_task, &cons_arg);

    coro_wait_tasks(tasks, N_PRODS, CORO_TASK_WAIT_ALL);
    coro_queue_closewrite(queue);

    coro_wait_tasks(&(tasks[N_PRODS]), 1, CORO_TASK_WAIT_FIRST);

    for (size_t i = 0; i < N_PRODS + 1; ++i) {
        coro_task_join(tasks[i]);
    }

    assert(val == (N_PRODS * N_VALS_P_PROD));

    return 0;
}

int main()
{
    struct coro_loop *loop = coro_new_loop(0);

    assert(loop);

    struct coro_task *task = coro_create_task(loop, startup_task, NULL);

    coro_run(loop);
    coro_task_join(task);
    coro_free_loop(loop);

    return 0;
}
