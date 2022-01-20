#include <assert.h>
#include <coro.h>

#define N_VALS (128)
#define N_TASKS (16)

int vals[N_VALS] = {0};

void *consumer_entry(void *arg)
{
    struct coro_queue *queue = arg;

    for (;;) {
        int *at = coro_queue_pop(queue);

        if (at == NULL) {
            break;
        }

        *at = 1;
        coro_yeild();
    }

    return NULL;
}

void *producer_entry(void *arg)
{
    struct coro_queue *queue = arg;

    for (size_t i = 0; i < N_VALS; ++i) {
        if (i % N_TASKS == 0) {
            coro_yeild();
        }
        coro_queue_push(queue, &(vals[i]), NULL);
    }

    coro_queue_closewrite(queue);

    return NULL;
}

int main() {
    struct coro_loop *loop = coro_new_loop(0);
    assert(loop);

    struct coro_task *consumers[N_TASKS] = {0};
    struct coro_task *producer = NULL;

    struct coro_queue *queue = coro_queue_new(loop);
    assert(queue);

    producer = coro_create_task(loop, producer_entry, queue);
    coro_task_set_name(producer, "Producer");
    assert(producer);
    for (size_t i = 0; i < N_TASKS; ++i) {
        char buf[32];
        consumers[i] = coro_create_task(loop, consumer_entry, queue);
        assert(consumers[i]);
        snprintf(buf, 32, "Consumer %zu", i);
        coro_task_set_name(consumers[i], buf);
    }

    coro_run(loop);
    coro_queue_delete(queue);
    coro_free_loop(loop);

    for (size_t i = 0; i < N_VALS; ++i) {
        if (!vals[i]) {
            printf("%zu vals not zero\n", i);
            assert(vals[i]);
        }
    }
    return 0;
}
