#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <coro.h>
#include <coro_ev.h>
#include <scheduler.h>
#include <task.h>

#define DEFAULT_STACK_SIZE (4096 * 4)

struct coro_loop {
    struct ev_loop *_loop;
    struct coro_scheduler *_sched;
};

static struct coro_loop *g_active_loop;

struct coro_loop *coro_new_loop(int flags)
{
    (void) flags;
    struct coro_loop *c = NULL;

    c = calloc(1, sizeof(struct coro_loop));
    if (!c) {
        goto error;
    }

    c->_loop = ev_loop_new(EVFLAG_AUTO);
    if (!c->_loop) {
        goto error;
    }

    c->_sched = coro_scheduler_new();
    if (!c->_sched) {
        goto error;
    }

    coro_sched_set_loop(c->_sched, c);

    return c;

error:
    coro_free_loop(c);
    return NULL;
}

void coro_free_loop(struct coro_loop *c)
{
    if (NULL == c) {
        return;
    }

    if (c->_sched) {
        coro_scheduler_free(c->_sched);
    }

    if (c->_loop) {
        ev_loop_destroy(c->_loop);
    }

    free(c);
}

int coro_run(struct coro_loop *l)
{
    int rc;

    g_active_loop = l;
    rc = ev_run(l->_loop, 0);
    g_active_loop = NULL;

    return rc;
}

struct coro_loop *coro_current(void)
{
    return g_active_loop;
}

struct coro_task *coro_create_task(struct coro_loop *loop,
                                   coro_task_entry_f entry, void *arg)
{
   struct coro_task *task;

   if (NULL == loop) {
       assert(g_active_loop);
       loop = g_active_loop;
   }

   task = task_new(DEFAULT_STACK_SIZE);

    if (!task) {
       return NULL;
    }

    task->entry = entry;
    task->arg = arg;
    task->sched = loop->_sched;

    ev_idle_init(&task->ev_watcher.idle, task);
    ev_idle_start(loop->_loop, &task->ev_watcher.idle);

    task->watcher_type = CORO_IDLE;
    
    return task;
}

bool coro_task_running(struct coro_task *task)
{
    return task->state != TASK_STATE_FINISHED;
}

struct coro_loop *coro_task_parent(struct coro_task *task)
{
    return coro_sched_loop(task->sched);
}

int coro_cancel_task(struct coro_task *task)
{
    if (coro_sched_active(task->sched) == task) {
        errno = EINVAL;
        return -1;
    }

    task_free(task);
    return 0;
}

void *coro_task_join(struct coro_task *task)
{
    void *ret;

    if (coro_task_running(task)) {
        return NULL;
    }

    ret = task->ret;
    task_free(task);

    return ret;
}

void *coro_await(struct coro_task *task)
{
    void *ret;

    coro_await_many(&task, 1, CORO_WAIT_ALL);
    ret = task->ret;
    task_free(task);
    return ret;
}

void coro_await_many(struct coro_task **task, size_t len, enum coro_wait_how how)
{
    struct coro_task *_curr_task;
    bool one_running;

    assert(g_active_loop);

    _curr_task = coro_sched_active(g_active_loop->_sched);
    assert(_curr_task);

    ev_async_init(&_curr_task->ev_watcher.idle, _curr_task);
    ev_async_start(g_active_loop->_loop, &_curr_task->ev_watcher.async);

    _curr_task->watcher_type = CORO_ASYNC;
    for (size_t i = 0; i < len; ++i) {
        assert(task[i]->waiter == NULL);
        task[i]->waiter = &_curr_task->ev_watcher.async;
    }

    coro_swap_to_sched(g_active_loop->_sched);

    if (CORO_WAIT_FIRST == how) {
        return;
    }

    do {
        one_running = false;

        ev_async_init(&_curr_task->ev_watcher.idle, _curr_task);

        for (size_t i = 0; i < len; ++i) {
            if (coro_task_running(task[i])) {
                printf("Task %p is still running\n", task[i]);
                task[i]->waiter = &_curr_task->ev_watcher.async;
                one_running = true;
            }
        }

        if (one_running) {
            ev_async_start(g_active_loop->_loop, &_curr_task->ev_watcher.async);

            coro_swap_to_sched(g_active_loop->_sched);
        }

    } while (one_running);

    printf("Leave loop\n");
}

void coro_yeild()
{
    struct coro_task *_curr_task;

    _curr_task = coro_sched_active(g_active_loop->_sched);
    ev_idle_init(&_curr_task->ev_watcher.idle, _curr_task);
    ev_idle_start(g_active_loop->_loop, &_curr_task->ev_watcher.idle);

    _curr_task->watcher_type = CORO_IDLE;

    coro_swap_to_sched(g_active_loop->_sched);
}

struct ev_loop *coro_loop_backend(struct coro_loop *l)
{
    return l->_loop;
}
