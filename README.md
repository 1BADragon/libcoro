# Coroutine Library

My simple learning experience coroutine library. The coroutine frame is built on top of
libev for event triggering. The coroutines have their own exectuion stack. Currently, 
this is a very Linux only library. It might work with other Unix flavor'ed kernel's but 
has not been attempted. 

## Some Features:
 * Coroutines
 * Inter-coroutine data queue
 * Written in C
 * Multi value yeilding (think python `yeild` expressions)
 * IO Wrapper functions

## Example:

```c
#include <stdio.h>

#include <coro.h>

static void *task_entry(void *)
{
    for (size_t i = 0; i < 5; ++i) {
        printf("Hello from %p\n", coro_task_name(coro_current_task()));
        coro_sleepms(100);
    }
    return NULL;
}

int main()
{
    struct coro_loop *loop = coro_loop_new(0);

    struct coro_task *task = coro_task_create(loop, task_entry, NULL);

    coro_run();

    coro_task_join(task);
    coro_loop_free(loop);

    return 0;
}
```
