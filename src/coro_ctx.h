#ifndef CORO_CTX_H
#define CORO_CTX_H

struct coro_ctx;

void swap_coro(struct coro_ctx *to, struct coro_ctx *from);

#endif // CORO_CTX_H