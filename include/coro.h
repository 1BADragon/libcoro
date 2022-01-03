#ifndef CORO_H
#define CORO_H

#include <stdbool.h>

struct coro_loop;
struct coro_task;

typedef void *(*coro_task_entry_f)(void *);

struct coro_loop *coro_new_loop(int flags);
void coro_free_loop(struct coro_loop *l);
int coro_run(struct coro_loop *l);

// Task building functions
struct coro_task *coro_create_task(struct coro_loop *loop,
                                   coro_task_entry_f entry, void *arg);

// Task status functions
bool coro_task_running(struct coro_task *task);
struct coro_loop *coro_task_parent(struct coro_task *task);

// Task destroying functions
int coro_cancel_task(struct coro_task *task);
void *coro_task_join(struct coro_task *task);

#endif // CORO_H
