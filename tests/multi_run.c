#include <assert.h>
#include <coro.h>

#define N_TASKS (1000)

void *task_entry(void *arg)
{
    int *i = arg;
    *i = 1;
    return i;
}

int main()
{
    int vals[N_TASKS];
    struct coro_loop *loop = coro_new_loop(0);

    for (size_t i = 0; i < N_TASKS; ++i) {
        coro_create_task(loop, &task_entry, &(vals[i]));
    }

    coro_run(loop);

    for (size_t i = 0; i < N_TASKS; ++i) {
        assert(vals[i]);
    }

    coro_free_loop(loop);

    return 0;
}
