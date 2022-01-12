#ifndef CORO_H
#define CORO_H

#include <stdbool.h>
#include <stddef.h>

// dumb macro to help dev's note coro's
#define coro

struct coro_loop;
struct coro_task;

typedef void *(*coro_task_entry_f)(void *);

enum coro_wait_how {
    CORO_WAIT_FIRST,
    CORO_WAIT_ALL
};

struct coro_loop *coro_new_loop(int flags);
void coro_free_loop(struct coro_loop *l);
int coro_run(struct coro_loop *l);
struct coro_loop *coro_current(void);
struct coro_task *coro_current_task(void);

// Task building functions
struct coro_task *coro_create_task(struct coro_loop *loop,
                                   coro_task_entry_f entry, void *arg);

// Task status functions
bool coro_task_running(struct coro_task *task);
struct coro_loop *coro_task_parent(struct coro_task *task);

// Task destroying functions
int coro_cancel_task(struct coro_task *task);
// Wait from outside the loop
void *coro_task_join(struct coro_task *task);

// Wait from within the loop (as a coro)
// Cleans the awaited task
void *coro_await(struct coro_task *task);
// Does not clean the awaited tasks so user can determine what to do
void coro_await_many(struct coro_task **task, size_t len, enum coro_wait_how how);

// Coro yeilding and IO functions
// Generic yeild, resumes after swapping to the scheduler
void coro_yeild();

// Sleeping functions
void coro_sleep(unsigned long amnt);
void coro_sleepms(unsigned long amnt);

// Coro hook functions
void coro_hook_set_alloc(void *(*func)(long));
void *coro_alloc(long size);
void *coro_zalloc(long size);

void coro_hook_set_free(void (*func)(void *));
void coro_free(void *ptr);

void coro_hook_set_realloc(void *(*func)(void *, unsigned long));
void *coro_realloc(void *ptr, long s);

void coro_hook_set_stacksize(long (*func)(void));
long coro_stacksize(void);

void coro_hook_set_stackalloc(void *(*func)(unsigned long));
void *coro_stackalloc(unsigned long size);

void coro_hook_set_stackunalloc(void (*func)(void *, unsigned long));
void coro_stackunalloc(void *ptr, unsigned long size);

#endif // CORO_H
