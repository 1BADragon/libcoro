#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>

#include <coro.h>
#include <coro_ev.h>
#include <task.h>

#define DEFAULT_STACK_SIZE (4096 * 6)

struct coro_loop {
    struct ev_loop *_loop;

    struct coro_ctx sched_ctx;
    struct coro_task *active;
    struct list_head tasks;
};

enum coro_task_state {
    TASK_STATE_INIT,
    TASK_STATE_RUNNING,
    TASK_STATE_FINISHED
};

enum coro_watcher_type {
    CORO_NONE,
    CORO_IO,
    CORO_IDLE,
    CORO_ASYNC,
};

union coro_watchers {
    ev_io io;
    ev_idle idle;
    ev_async async;
};

struct coro_task {
    struct coro_loop *owner;
    struct list_head node;

    int last_revent;

    coro_task_entry_f entry;
    void *arg;
    void *ret;

    enum coro_watcher_type watcher_type;
    union coro_watchers ev_watcher;

    // Set by those who are waiting for this task
    ev_async *waiter;

    struct coro_ctx ctx;
    enum coro_task_state state;
    uint8_t *stack;
    uint8_t *stack_top;
    size_t stack_size;

    // for debugging
    int ref_count;
};

static struct coro_loop *g_active_loop;

static int coro_event_trigger(struct coro_task *t, int revent);
static void coro_swap_to_sched(void);
static void coro_start(struct coro_task *t);

static bool is_coro(struct coro_task *in_question);

static void coro_swap(struct coro_ctx *in, struct coro_ctx *out);

// Task functions
static struct coro_task *task_new(size_t stack_size);
static void task_free(struct coro_task *task);
static void task_destroy_watcher(struct coro_task *t);
static int allocate_stack(struct coro_task *t, size_t size);

static void task_prepare_async(struct coro_task *t);
static void task_prepare_idle(struct coro_task *t);

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

    c->active = NULL;
    INIT_LIST_HEAD(&c->tasks);

    return c;

error:
    coro_free_loop(c);
    return NULL;
}

void coro_free_loop(struct coro_loop *c)
{
    struct coro_task *curr_task;
    struct coro_task *_safe_task;

    if (NULL == c) {
        return;
    }

    list_for_each_entry_safe(curr_task, _safe_task, &c->tasks, node) {
        list_del(&curr_task->node);
        task_free(curr_task);
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

struct coro_task *coro_current_task()
{
    if (!g_active_loop) {
        return NULL;
    }

    return g_active_loop->active;
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
    task->owner = loop;

    list_add_tail(&task->node, &loop->tasks);

    task_prepare_idle(task);
    
    return task;
}

bool coro_task_running(struct coro_task *task)
{
    return task->state != TASK_STATE_FINISHED;
}

struct coro_loop *coro_task_parent(struct coro_task *task)
{
    return task->owner;
}

int coro_cancel_task(struct coro_task *task)
{
    // Tasks cannot be canceled from within its own task
    if (task->owner->active == task) {
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

    _curr_task = g_active_loop->active;
    assert(_curr_task);

    do {
        int count = 0;
        one_running = false;

        for (size_t i = 0; i < len; ++i) {
            if (coro_task_running(task[i])) {
                assert(_curr_task->owner == g_active_loop);
                count++;
                task[i]->waiter = &_curr_task->ev_watcher.async;
                one_running = true;
            }
        }

        if (one_running) {
            task_prepare_async(_curr_task);
            coro_swap_to_sched();
        }

    } while (one_running && CORO_WAIT_FIRST != how);

    // Remove this to prevent strange things
    _curr_task->watcher_type = CORO_NONE;

    // Set all waiters back to NULL
    for (size_t i = 0; i < len; ++i) {
        task[i]->waiter = NULL;
    }

    task_destroy_watcher(_curr_task);
}

void coro_yeild()
{
    struct coro_task *_curr_task;

    _curr_task = g_active_loop->active;
    task_prepare_idle(_curr_task);

    coro_swap_to_sched();
}

/*************************
 * Defined by coro_ev.h  *
 ************************/

void coro_ev_cb_invoke(void *watcher, int revents)
{
    ev_watcher *_watcher = watcher;

    // Need to check if i own the task/cb or if this in internal to libev
    if (is_coro(_watcher->cb)) {
        coro_event_trigger(_watcher->cb, revents);
    } else {
        // so this is dumb
        ((void (*)(struct ev_loop *, void *, int))_watcher->cb)(g_active_loop->_loop,
                                                                watcher, revents);
    }
}

/**********************
 * Internal Functions *
 *********************/

static int coro_event_trigger(struct coro_task *t, int revent)
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
        t->owner->active = t;

        // transfer execution to the coro
        coro_swap(&t->ctx, &t->owner->sched_ctx);
        break;
    case TASK_STATE_RUNNING:
        // Set as active
        t->owner->active = t;
        // Resume execution in the coro
        coro_swap(&t->ctx, &t->owner->sched_ctx);
        break;
    case TASK_STATE_FINISHED:
        // This might be a stale watcher, this also
        // might be an error state
        break;
    }

    // Remove active status
    t->owner->active = NULL;

    return 0;
}

static void coro_swap_to_sched()
{
    assert(g_active_loop->active);
    coro_swap(&g_active_loop->sched_ctx, &g_active_loop->active->ctx);
}

static void coro_start(struct coro_task *t)
{
    t->state = TASK_STATE_RUNNING;

    // call the coroutine entry
    t->ret = t->entry(t->arg);

    // Kill any pending watcher for this task, there should not be one but
    // do this anyway to prevent some crazyness in the event loop
    task_destroy_watcher(t);

    // If another coroutine is waiting for this one to finish then signal it
    if (t->waiter) {
        ev_async_send(t->owner->_loop, t->waiter);
    }

    t->state = TASK_STATE_FINISHED;

    // Hopefully this never returns from this point
    coro_swap(&t->owner->sched_ctx, &t->ctx);
}

static bool is_coro(struct coro_task *in_question)
{
    struct coro_task *task;

    list_for_each_entry(task, &g_active_loop->tasks, node) {
        if (task == in_question) {
            return true;
        }
    }

    return false;
}

static void coro_swap(struct coro_ctx *in, struct coro_ctx *out)
{
    coro_swap_ctx(in, out);
}

/***************************
 * Task Functions          *
 **************************/

static struct coro_task *task_new(size_t stack_size)
{
    struct coro_task *task = NULL;

    task = calloc(1, sizeof(struct coro_task));
    if (!task) {
        goto error;
    }

    if (allocate_stack(task, stack_size)) {
        goto error;
    }
    task->state = TASK_STATE_INIT;

    // Make sure this is NULL
    task->waiter = NULL;
    task->ref_count = 0;

    return task;
error:
    task_free(task);
    return NULL;
}

static void task_free(struct coro_task *task)
{
    if (!task) {
        return;
    }

    list_del(&task->node);
    task_destroy_watcher(task);

    if (task->stack) {
        munmap(task->stack, task->stack_size);
    }

    if (task->ref_count > 0) {
        printf("Task %p has positive ref count: %d\n", task, task->ref_count);
    }

    free(task);

    if (g_active_loop && list_empty(&g_active_loop->tasks)) {
        ev_break(g_active_loop->_loop, EVBREAK_ALL);
    }
}

static void task_destroy_watcher(struct coro_task *t)
{
    struct ev_loop *loop;

    assert(t != NULL);
    assert(t->owner);

    loop = t->owner->_loop;

    if (t->watcher_type != CORO_NONE) {
        t->ref_count--;
    }

    switch (t->watcher_type) {
    case CORO_NONE:
        break;
    case CORO_IO:
        ev_io_stop(loop, &t->ev_watcher.io);
        break;
    case CORO_IDLE:
        ev_idle_stop(loop, &t->ev_watcher.idle);
        break;
    case CORO_ASYNC:
        ev_async_stop(loop, &t->ev_watcher.async);
        break;
    }

    t->watcher_type = CORO_NONE;
    memset(&t->ev_watcher, 0, sizeof(t->ev_watcher));
}

static int allocate_stack(struct coro_task *t, size_t size)
{
    t->stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);

    if (!t->stack) {
        return -1;
    }

    // create a protected page to prevent stack overflow
    mprotect(t->stack, 4096, PROT_NONE);

    t->stack_size = size;
    t->stack_top =
            (uint8_t *)((
                (uintptr_t)t->stack + t->stack_size) & ~0xf
                        );
    return 0;
}

static void task_prepare_async(struct coro_task *t)
{
    t->ref_count++;
    t->watcher_type = CORO_ASYNC;
    ev_async_init(&t->ev_watcher.async, t);
    ev_async_start(t->owner->_loop, &t->ev_watcher.async);
}

static void task_prepare_idle(struct coro_task *t)
{
    t->ref_count++;
    t->watcher_type = CORO_IDLE;
    ev_idle_init(&t->ev_watcher.idle, t);
    ev_idle_start(t->owner->_loop, &t->ev_watcher.idle);
}
