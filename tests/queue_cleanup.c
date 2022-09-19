#include <stdlib.h>
#include <coro.h>

#include "test_harness.h"

void *main_task(void *arg) {
    struct coro_queue *queue = coro_queue_new(NULL);

    assert(queue != NULL);

    for (size_t i = 0; i < 16; ++i) {
        int *v = malloc(sizeof(int));
        assert(v != NULL);

        int rc = coro_queue_push(queue, v, &free);
        assert(rc == 0);
    }

    coro_queue_delete(queue);

    *(int *)arg = 1;
    return arg;
}
