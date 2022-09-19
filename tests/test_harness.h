#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

void *main_task(void *arg);

#define STRINGIZE(a) #a

#define assert(cond) _assert((cond), STRINGIZE(cond))

static inline void _assert(bool cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "Test condition %s failed\n", msg);
        abort();
    }
}

#endif
