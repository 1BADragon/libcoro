#include <assert.h>
#include <coro.h>

#define N_VALS (1000)

static int g_vals[N_VALS];

static void *producer_task(void *arg)
{
    struct coro_queue *queue = arg;

    for (size_t i = 0; i < N_VALS; ++i) {
        coro_queue_push(queue, &(g_vals[i]), NULL);
    }

    coro_queue_closewrite(queue);
    return NULL;
}

static void *consumer_task(void *arg)
{
    struct coro_queue *queue = arg;

    for (;;) {
        int *val = coro_queue_pop(queue);

        if (val == NULL) {
            break;
        }

        *val = 1;
    }

    return NULL;
}

int main()
{
    struct coro_loop *loop = coro_new_loop(0);

    struct coro_queue *queue = coro_queue_new(loop);

    coro_create_task(loop, &producer_task, queue);
    coro_create_task(loop, &consumer_task, queue);

    coro_run(loop);

    coro_queue_delete(queue);
    coro_free_loop(loop);

    for (size_t i = 0; i < N_VALS; ++i) {
        assert(g_vals[i]);
    }

    return 0;
}
