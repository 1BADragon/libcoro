#ifndef CORO_H
#define CORO_H

#include <coro/scheduler.h>
#include <coro/task.h>

struct coro *coro_new(int flags);
void coro_free(struct coro *c);

#endif // CORO_H
