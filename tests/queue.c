#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <coro.h>

coro static void *reader(void *data)
{
    struct coro_queue *queue = data;

    for (;;) {
        char *c = coro_queue_pop(queue);
        if (!c) {
            break;
        }
        putc(*c, stdout);
        fflush(stdout);
    }

    return NULL;
}

coro static void *writer(void *data)
{
    struct coro_queue *queue = data;

    const char *message = "This is a test message!!!\n";

    for (size_t i = 0; i < strlen(message); ++i) {
        coro_queue_push(queue, (void *)&message[i], NULL);
        coro_sleepms(10);
    }

    coro_queue_delete(queue);

    return NULL;
}

int main()
{
    struct coro_loop *loop = coro_new_loop(0);

    struct coro_queue *queue = coro_queue_new(loop);

    struct coro_task *rt = coro_create_task(loop, reader, queue);
    struct coro_task *wt = coro_create_task(loop, writer, queue);

    coro_run(loop);
    coro_task_join(rt);
    coro_task_join(wt);

    coro_free_loop(loop);

    return 0;
}
