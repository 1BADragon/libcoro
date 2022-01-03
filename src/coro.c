#include <stdlib.h>
#include <errno.h>

#include <coro.h>
#include <coro_ev.h>
#include <scheduler.h>
#include <task.h>

#define DEFAULT_STACK_SIZE (4096 * 16)

struct coro_loop {
    struct ev_loop *_loop;
    struct coro_scheduler *_sched;
};

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
    return ev_run(l->_loop, 0);
}

struct coro_task *coro_create_task(struct coro_loop *loop,
                                   coro_task_entry_f entry, void *arg)
{
   struct coro_task *task = task_new(DEFAULT_STACK_SIZE);

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
    if (coro_task_running(task)) {
        // coro wait for task to finish
    }

    return task->ret;
}

struct ev_loop *coro_loop_backend(struct coro_loop *l)
{
    return l->_loop;
}
