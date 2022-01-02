#ifndef CORO_H
#define CORO_H

#include <stdbool.h>

struct coro_loop;
struct coro_task;

typedef void *(*coro_task_entry_f)(void *);

struct coro_loop *coro_new_loop(int flags);
void coro_free_loop(struct coro_loop *c);

struct task *coro_create_task(coro_task_entry_f entry, void *arg);
bool coro_task_running(struct coro_task *task);
struct coro_loop *coro_task_parent(struct coro_task *task);
// Releives ownership from caller
int coro_cancel_task(struct coro_task *task);
void *coro_task_join(struct coro_task *task);

#endif // CORO_H
