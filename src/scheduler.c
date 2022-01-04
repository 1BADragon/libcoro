#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <coro_int.h>
#include <coro_arch.h>
#include <scheduler.h>
#include <task.h>

struct coro_scheduler {
    struct coro_ctx sched_ctx;
    struct coro_task *active;
    struct list_head running;

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

    INIT_LIST_HEAD(&new_cs->running);

    return new_cs;

exit:
    coro_scheduler_free(new_cs);
    return NULL;
}

void coro_scheduler_free(struct coro_scheduler *sched)
{
    struct coro_task *curr;
    struct coro_task *_safe;

    if (!sched) {
        return;
    }

    // Delete all running task contexts
    list_for_each_entry_safe(curr, _safe, &sched->running, node) {
        list_del(&curr->node);
        task_free(curr);
    }

    free(sched);
}

int coro_event_trigger(struct coro_task *t, int revent)
{
    printf("%s: task: %p\n", __func__, t);

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

void coro_swap_to_sched(struct coro_scheduler *sched)
{
    assert(sched->active);
    coro_swap(&sched->sched_ctx, &sched->active->ctx);
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

    // at this point t->sched is set so add this task to its list
    list_add_tail(&t->node, &t->sched->running);

    // call the coroutine entry
    t->ret = t->entry(t->arg);

    // the coro is done, remove from running list
    list_del(&t->node);

    // Kill any pending watcher for this task, there should not be one but
    // do this anyway to prevent some crazyness in the event loop
    task_destroy_watcher(t);

    // If another coroutine is waiting for this one to finish then signal it
    if (t->waiter) {
        ev_async_send(coro_loop_backend(coro_sched_loop(t->sched)), t->waiter);
    }

    t->state = TASK_STATE_FINISHED;

    // Hopefully this never returns from this point
    coro_swap(&t->sched->sched_ctx, &t->ctx);
}
