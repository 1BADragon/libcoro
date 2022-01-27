#include <stdlib.h>
#include <coro.h>


int main() {
    struct coro_loop *loop = coro_new_loop(0);

    struct coro_queue *queue = coro_queue_new(loop);

    for (size_t i = 0; i < 16; ++i) {
        int *v = malloc(sizeof(int));

        coro_queue_push(queue, v, &free);
    }

    coro_queue_delete(queue);
    coro_free_loop(loop);
    return 0;
}
