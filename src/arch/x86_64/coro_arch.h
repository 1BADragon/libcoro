#ifndef CORO_ARCH_H
#define CORO_ARCH_H

#include <stdint.h>

struct coro_ctx {
    void *pc;
    void *sp;

    void *rbx;
    void *rbp;
    void *r12;
    void *r13;
    void *r14;
    void *r15;

    void *rdi;
};

void coro_ctx_setup(struct coro_ctx *ctx, void *stack, void *entry, void *val)
{
    ctx->sp = stack;
    *(void **)ctx->sp = entry;
    ctx->rdi = val;
}

#endif
