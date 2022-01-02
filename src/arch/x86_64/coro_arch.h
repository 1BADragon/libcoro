#ifndef CORO_ARCH_H
#define CORO_ARCH_H

#include <stdint.h>

struct coro_ctx {
    void *pc;
    void *sp;
};

#endif
