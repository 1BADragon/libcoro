#include <stdio.h>
#include <coro.h>

static void *hello_world(void *arg)
{
    (void) arg;
    printf("Hello, World!\n");

    return NULL;
}

int main()
{
    struct coro_loop *loop;

    loop = coro_new_loop(0);

    if (!loop) {
        return -1;
    }

    coro_create_task(loop, hello_world, NULL);

    return coro_run(loop);
}
