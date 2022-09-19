#include <stdlib.h>
#include <coro.h>
#include "test_harness.h"

static size_t g_n_backends = 1;
static int g_backends[] = {
    CORO_BACKEND_EV,
};

int main() {
    for (size_t i = 0; i < g_n_backends; ++i) {
        int arg = 0;
        struct coro_loop *loop = coro_new_loop(g_backends[i]);
        assert(loop);

        struct coro_task *task = coro_create_task(loop, main_task, &arg);
        assert(task);

        coro_run(loop);

        int *res = coro_task_join(task);
        assert(res);
        assert(*res);
        coro_free_loop(loop);
    }
}
