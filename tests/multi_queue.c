#include <stdlib.h>
#include <coro.h>

#include "test_harness.h"

struct consumer_args {
    int *val;
    struct coro_queue *queue;
};

void *producer_task(void *arg)
{
    struct coro_queue *queue = arg;

    for (size_t i = 0; i < N_VALS_P_PROD; ++i) {
        int *val = malloc(sizeof(int));

        assert(NULL != val);

        *val = i;
        // no free function so memory leaks can be detected
        coro_queue_push(queue, val, NULL);
        coro_yeild();
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

void *main_task(void *arg)
{
    int val = 0;
    struct consumer_args cons_arg;
    struct coro_queue *queue = coro_queue_new(NULL);
    assert(queue);

    struct coro_task *tasks[N_PRODS + N_CONSUM] = {0};

    for (size_t i = 0; i < N_PRODS; ++i) {
        tasks[i] = coro_create_task(NULL, producer_task, queue);
        coro_yeild();
    }

    cons_arg.queue = queue;
    cons_arg.val = &val;

    for (size_t i = 0; i < N_CONSUM; ++i) {
        tasks[i + N_PRODS] = coro_create_task(NULL, consumer_task, &cons_arg);
    }

    coro_wait_tasks(tasks, N_PRODS, CORO_TASK_WAIT_ALL);
    coro_queue_closewrite(queue);

    coro_wait_tasks(&(tasks[N_PRODS]), N_CONSUM, CORO_TASK_WAIT_FIRST);

    for (size_t i = 0; i < N_PRODS + N_CONSUM; ++i) {
        coro_task_join(tasks[i]);
    }

    assert(val == (N_PRODS * N_VALS_P_PROD));

    *(int *)arg = 1;
    return arg;
}
