#include <setjmp.h>

#include <coro_arch.h>
#include <scheduler.h>
#include <task.h>

struct coro_scheduler {
    struct coro_ctx sched_ctx;
    struct coro_task *active;
};

static void coro_start(struct coro_task *t);

int coro_event_trigger(struct coro_task *t, int revent)
{
    t->last_revent = revent;

    // called directly
    switch(t->state) {
    case TASK_STATE_INIT:
        // set the required values
        t->ctx.sp = t->stack + t->stack_size;
        t->ctx.pc = &coro_start;

        // Set it to the new active coro
        t->sched->active = t;

        // transfer execution to the coro
        swap_coro(&t->ctx, &t->sched->sched_ctx);
        break;
    case TASK_STATE_RUNNING:
        // Resume execution in the coro
        swap_coro(&t->ctx, &t->sched->sched_ctx);
        break;
    case TASK_STATE_FINISHED:
        // This might be a stale watcher, this also
        // might be an error state
        break;
    }

    return 0;
}

static void coro_start(struct coro_task *t)
{
    t->state = TASK_STATE_RUNNING;

    // call the coroutine entry
    t->ret = t->entry(t->arg);

    t->state = TASK_STATE_FINISHED;

    // Hopefully this never returns from this point
    swap_coro(&t->sched->sched_ctx, &t->ctx);
}
