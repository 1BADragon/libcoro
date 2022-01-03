#include <stdlib.h>
#include <stdio.h>
#include <coro_arch.h>
#include <scheduler.h>
#include <task.h>

struct coro_scheduler {
    struct coro_ctx sched_ctx;
    struct coro_task *active;

    struct coro_loop *loop;
};

static void coro_start(struct coro_task *t);

struct coro_scheduler *coro_scheduler_new()
{
    struct coro_scheduler *new_cs;

    new_cs = calloc(1, sizeof(struct coro_scheduler));
    if (!new_cs) {
        goto exit;
    }

    new_cs->active = NULL;

    return new_cs;

exit:
    coro_scheduler_free(new_cs);
    return NULL;
}

void coro_scheduler_free(struct coro_scheduler *sched)
{
    if (!sched) {
        return;
    }

    free(sched);
}

int coro_event_trigger(struct coro_task *t, int revent)
{
    t->last_revent = revent;

    // Reset the watcher state
    task_destroy_watcher(t);

    // called directly
    switch(t->state) {
    case TASK_STATE_INIT:
        // set the required values
        t->ctx.sp = t->stack_top;
        t->ctx.pc = &coro_start;
        t->ctx.rdi = t;

        // Set it to the new active coro
        t->sched->active = t;

        // transfer execution to the coro
        coro_swap(&t->ctx, &t->sched->sched_ctx);
        break;
    case TASK_STATE_RUNNING:
        // Set as active
        t->sched->active = t;
        // Resume execution in the coro
        coro_swap(&t->ctx, &t->sched->sched_ctx);
        break;
    case TASK_STATE_FINISHED:
        // This might be a stale watcher, this also
        // might be an error state
        break;
    }

    // Remove active status
    t->sched->active = NULL;

    return 0;
}

void coro_sched_set_loop(struct coro_scheduler *s,
                         struct coro_loop *l)
{
    s->loop = l;
}

struct coro_task *coro_sched_active(struct coro_scheduler *s)
{
    return s->active;
}

struct coro_loop *coro_sched_loop(struct coro_scheduler *s)
{
    return s->loop;
}

static void coro_start(struct coro_task *t)
{
    t->state = TASK_STATE_RUNNING;

    // call the coroutine entry
    t->ret = t->entry(t->arg);

    // Kill any pending watcher for this task;
    task_destroy_watcher(t);

    t->state = TASK_STATE_FINISHED;

    // Hopefully this never returns from this point
    coro_swap(&t->sched->sched_ctx, &t->ctx);
}
