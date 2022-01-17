#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

#include <coro.h>
#include <coro_ev.h>
#include <task.h>

#ifdef MULTI_THREAD
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL
#endif

struct coro_loop {
    struct ev_loop *_loop;

    struct coro_ctx sched_ctx;
    struct coro_task *active;
    struct list_head tasks;
    struct list_head queues;
};

enum coro_watcher_type {
    CORO_NONE,
    CORO_IO,
    CORO_IDLE,
    CORO_ASYNC,
    CORO_TIMER,
};

struct coro_trigger {
    union {
        ev_io io;
        ev_idle idle;
        ev_async async;
        ev_timer timer;
    };
    enum coro_watcher_type type;
    struct list_head tasks;
    struct coro_loop *loop;
    unsigned int ref_count;
};

struct coro_task {
    struct coro_loop *owner;
    struct list_head node;

    struct list_head trigger_list;
    struct coro_trigger *pending;

    int last_revent;

    coro_task_entry_f entry;
    void *arg;
    void *ret;

    // Set by those who are waiting for this task
    struct coro_trigger *waiter;

    struct coro_ctx ctx;
    enum coro_task_state state;
    uint8_t *stack;
    uint8_t *stack_top;
    size_t stack_size;

    char *name;
};

struct coro_queue_data {
    struct list_head node;
    void *data;
    void (*free_f)(void *);
};

struct coro_queue {
    struct coro_loop *parent;
    struct list_head node;

    struct list_head data;
    struct coro_trigger *sig;
};

struct coro_sentinal {

};

static struct coro_sentinal g_sentinal;

THREAD_LOCAL static struct coro_loop *g_active_loop;

static int coro_event_trigger(struct coro_task *t, int revent);
static void coro_swap_to_sched(void);
static void coro_start(struct coro_task *t);
static void coro_swap(struct coro_ctx *in, struct coro_ctx *out);

// Task functions
static struct coro_task *task_new(size_t stack_size);
static void task_free(struct coro_task *task);
static void task_remove_pending(struct coro_task *task);
static int allocate_stack(struct coro_task *t, size_t size);

// Trigger Functions
static struct coro_trigger *trigger_new(struct coro_loop *loop);
static struct coro_trigger *trigger_new_async(struct coro_loop *loop);
static struct coro_trigger *trigger_new_idle(struct coro_loop *loop);
static struct coro_trigger *trigger_new_timer(struct coro_loop *loop, ev_tstamp time);
static struct coro_trigger *trigger_new_io(struct coro_loop *loop, int fd, int how);

static void trigger_add_watcher(struct coro_trigger *trigger, struct coro_task *task);
static void trigger_del_watcher(struct coro_trigger *trigger, struct coro_task *task);
static void trigger_inc_ref(struct coro_trigger *trigger);
static void trigger_dec_ref(struct coro_trigger *trigger);
static void trigger_destroy(struct coro_trigger *trigger);

// Queue helpers
static struct coro_queue_data *queue_data_build(void *data, void (*)(void *));
static void queue_data_destroy(struct coro_queue_data *data);

struct coro_loop *coro_new_loop(int flags)
{
    (void) flags;
    struct coro_loop *c = NULL;

    c = coro_zalloc(sizeof(struct coro_loop));
    if (!c) {
        goto error;
    }

    c->_loop = ev_loop_new(EVFLAG_AUTO);
    if (!c->_loop) {
        goto error;
    }

    c->active = NULL;
    INIT_LIST_HEAD(&c->tasks);
    INIT_LIST_HEAD(&c->queues);

    ev_set_allocator(coro_realloc);

    return c;

error:
    coro_free_loop(c);
    return NULL;
}

void coro_free_loop(struct coro_loop *c)
{
    struct coro_task *curr_task;
    struct coro_task *_safe_task;
    struct coro_queue *curr_queue;
    struct coro_queue *_safe_queue;

    if (NULL == c) {
        return;
    }

    list_for_each_entry_safe(curr_task, _safe_task, &c->tasks, node) {
        list_del(&curr_task->node);
        task_free(curr_task);
    }

    list_for_each_entry_safe(curr_queue, _safe_queue, &c->queues, node) {
        list_del(&curr_queue->node);
        coro_queue_delete(curr_queue);
    }

    if (c->_loop) {
        ev_loop_destroy(c->_loop);
    }

    coro_free(c);
}

int coro_run(struct coro_loop *l)
{
    int rc;

    if (g_active_loop) {
        return -1;
    }

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
    struct coro_trigger *trigger = NULL;

    if (NULL == loop) {
        assert(g_active_loop);
        loop = g_active_loop;
    }

    task = task_new(coro_stacksize());

    if (!task) {
        return NULL;
    }

    task->entry = entry;
    task->arg = arg;
    task->owner = loop;

    list_add_tail(&task->node, &loop->tasks);

    trigger = trigger_new_idle(loop);
    if (!trigger) {
        task_free(task);
        return NULL;
    }

    trigger_add_watcher(trigger, task);
    trigger_dec_ref(trigger);

    return task;
}

bool coro_task_running(struct coro_task *task)
{
    return coro_task_state(task) != TASK_STATE_FINISHED;
}

struct coro_loop *coro_task_parent(struct coro_task *task)
{
    return task->owner;
}

enum coro_task_state coro_task_state(struct coro_task *task)
{
    return task->state;
}

int coro_task_set_name(struct coro_task *task, const char *name)
{
    if (NULL == name) {
        if (task->name) {
            coro_free(task->name);
            task->name = NULL;
        }
        return 0;
    }

    size_t len = strlen(name);

    void *ptr = coro_realloc(task->name, len + 1);
    if (!ptr) {
        // ENOMEM
        return -1;
    }

    task->name = ptr;
    memcpy(task->name, name, len);
    task->name[len] = '\0';
    return 0;
}

const char *coro_task_name(struct coro_task *task)
{
    if (!task) {
        return "(null)";
    }

    return task->name;
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

struct coro_queue *coro_queue_new(struct coro_loop *loop)
{
    struct coro_queue *new_queue;

    if (NULL == loop) {
        if (g_active_loop == NULL) {
            errno = EINVAL;
            return NULL;
        }

        loop = g_active_loop;
    }

    new_queue = coro_zalloc(sizeof(struct coro_queue));
    if (!new_queue) {
        return NULL;
    }

    new_queue->parent = loop;
    new_queue->sig = NULL;

    INIT_LIST_HEAD(&new_queue->data);
    list_add_tail(&new_queue->node, &loop->queues);
    return new_queue;
}

void coro_queue_delete(struct coro_queue *queue)
{
    struct coro_queue_data *data;
    struct coro_queue_data *_safe_data;

    list_for_each_entry_safe(data, _safe_data, &queue->data, node) {
        list_del(&data->node);
        queue_data_destroy(data);
    }

    if (queue->sig) {
        ev_feed_event(queue->parent->_loop, queue->sig, EV_CUSTOM);
    }

    list_del(&queue->node);

    coro_free(queue);
}

int coro_queue_push(struct coro_queue *queue, void *data, void (*free_f)(void *))
{
    struct coro_queue_data *chunk = queue_data_build(data, free_f);

    if (!chunk) {
        return -1;
    }

    list_add_tail(&chunk->node, &queue->data);
    ev_async_send(queue->parent->_loop, &queue->sig->async);

    return 0;
}

void *coro_queue_pop(struct coro_queue *queue)
{
    void *ret;
    struct coro_task *curr_task;

    curr_task = coro_current_task();
    if (!curr_task) {
        return NULL;
    }

    if (queue->sig) {
        return NULL;
    }

    for (;;) {
        ret = coro_queue_pop_nowait(queue);
        if (ret) {
            return ret;
        }

        trigger_add_watcher(queue->sig, curr_task);
        coro_swap_to_sched();
        if (curr_task->last_revent == EV_CUSTOM) {
            // indicates the queue was closed..
            return NULL;
        }
        queue->sig = NULL;
    }
}

void *coro_queue_pop_nowait(struct coro_queue *queue)
{
    struct coro_queue_data *data;

    data = list_first_entry_or_null(&queue->data, struct coro_queue_data, node);

    if (!data) {
        return NULL;
    }

    void *ptr = data->data;

    queue_data_destroy(data);
    return ptr;
}

void *coro_await(struct coro_task *task)
{
    void *ret;

    coro_wait_tasks(&task, 1, CORO_TASK_WAIT_ALL);
    ret = task->ret;
    task_free(task);
    return ret;
}

void coro_yeild()
{
    struct coro_task *_curr_task;
    struct coro_trigger *trigger;

    _curr_task = g_active_loop->active;

    trigger = trigger_new_idle(g_active_loop);

    trigger_add_watcher(trigger, _curr_task);
    trigger_dec_ref(trigger);

    coro_swap_to_sched();
}

void coro_wait_tasks(struct coro_task **task, size_t len, enum coro_task_wait_how how)
{
    struct coro_task *_curr_task;
    struct coro_trigger *trigger;
    bool one_running;

    assert(g_active_loop);

    _curr_task = g_active_loop->active;
    assert(_curr_task);

    trigger = trigger_new_async(g_active_loop);
    trigger_add_watcher(trigger, _curr_task);

    do {
        int count = 0;
        one_running = false;

        for (size_t i = 0; i < len; ++i) {
            if (coro_task_running(task[i])) {
                assert(_curr_task->owner == g_active_loop);
                count++;
                task[i]->waiter = trigger;
                one_running = true;
            }
        }

        if (one_running) {
            coro_swap_to_sched();
        }

    } while (one_running && CORO_TASK_WAIT_FIRST != how);

    // Remove this to prevent strange things
    trigger_del_watcher(trigger, _curr_task);

    // Set all waiters back to NULL
    for (size_t i = 0; i < len; ++i) {
        task[i]->waiter = NULL;
    }

    trigger_dec_ref(trigger);
}

void coro_sleep(unsigned long amnt)
{
    struct coro_trigger *trigger;

    trigger = trigger_new_timer(g_active_loop, (ev_tstamp)amnt);
    trigger_add_watcher(trigger, coro_current_task());
    trigger_dec_ref(trigger);
    coro_swap_to_sched();
}

void coro_sleepms(unsigned long amnt)
{
    ev_tstamp t_amnt = (ev_tstamp)amnt;
    struct coro_trigger *trigger;

    trigger = trigger_new_timer(g_active_loop, t_amnt / (ev_tstamp)1000.);
    trigger_add_watcher(trigger, coro_current_task());
    trigger_dec_ref(trigger);
    coro_swap_to_sched();
}

void coro_wait_fd(int fd, int how)
{
    struct coro_trigger *trigger;

    trigger = trigger_new_io(g_active_loop, fd, how);
    trigger_add_watcher(trigger, coro_current_task());
    trigger_dec_ref(trigger);
    coro_swap_to_sched();
}

long coro_read(int fd, void *buf, unsigned long len)
{
    long rc;

    for (;;) {
        coro_wait_fd(fd, CORO_FD_WAIT_READ);

        rc = read(fd, buf, len);
        if (rc == -1 && (errno == EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

long coro_write(int fd, const void *buf, unsigned long len)
{
    long rc;

    for (;;) {
        coro_wait_fd(fd, CORO_FD_WAIT_WRITE);

        rc = write(fd, buf, len);
        if (rc == -1 && (errno == EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

int coro_accept(int sock, struct sockaddr *addr, socklen_t *addr_len)
{
    int rc;

    for (;;) {
        coro_wait_fd(sock, CORO_FD_WAIT_READ);

        rc = accept(sock, addr, addr_len);
        if (rc == -1 && (errno = EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

long coro_recv(int sock, void *buf, unsigned long len, int flags)
{
    long rc;

    for (;;) {
        coro_wait_fd(sock, CORO_FD_WAIT_READ);

        rc = recv(sock, buf, len, flags);
        if (rc == -1 && (errno == EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

long coro_recvfrom(int sock, void *restrict buf, unsigned long len,
                   int flags, struct sockaddr *restrict src_addr,
                   socklen_t *restrict addrlen)
{
    long rc;

    for (;;) {
        coro_wait_fd(sock, CORO_FD_WAIT_READ);

        rc = recvfrom(sock, buf, len, flags, src_addr, addrlen);
        if (rc == -1 && (errno == EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

long coro_recvmsg(int sock, struct msghdr *msg, int flags)
{
    long rc;

    for (;;) {
        coro_wait_fd(sock, CORO_FD_WAIT_READ);

        rc = recvmsg(sock, msg, flags);
        if (rc == -1 && (errno == EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

long coro_send(int sock, const void *buf, unsigned long len, int flags)
{
    long rc;

    for (;;) {
        coro_wait_fd(sock, CORO_FD_WAIT_WRITE);

        rc = send(sock, buf, len, flags);
        if (rc == -1 && (errno == EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

long coro_sendto(int sock, const void *buf, unsigned long len, int flags,
                 const struct sockaddr *dest_addr, socklen_t addrlen)
{
    long rc;

    for (;;) {
        coro_wait_fd(sock, CORO_FD_WAIT_WRITE);

        rc = sendto(sock, buf, len, flags, dest_addr, addrlen);
        if (rc == -1 && (errno == EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

long coro_sendmsg(int sock, const struct msghdr *msg, int flags)
{
    long rc;

    for (;;) {
        coro_wait_fd(sock, CORO_FD_WAIT_WRITE);

        rc = sendmsg(sock, msg, flags);
        if (rc == -1 && (errno == EAGAIN ||
                         errno == EINTR)) {
            continue;
        }

        break;
    }

    return rc;
}

/*************************
 * Defined by coro_ev.h  *
 ************************/

void coro_ev_cb_invoke(void *watcher, int revents)
{
    struct coro_trigger *trigger;
    struct coro_task *task;
    struct coro_task *_safe;

    ev_watcher *_watcher = watcher;

    // Need to check if i own the task/cb or if this in internal to libev
    if (_watcher->cb == &g_sentinal) {
        trigger = (struct coro_trigger *)watcher;

        assert(!list_empty(&trigger->tasks));

        trigger_inc_ref(trigger);

        list_for_each_entry_safe(task, _safe, &trigger->tasks, trigger_list) {
            trigger_del_watcher(trigger, task);
            coro_event_trigger(task, revents);
        }

        trigger_dec_ref(trigger);

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

    // called directly
    switch(coro_task_state(t)) {
    case TASK_STATE_INIT:
        // set the required values
        coro_ctx_setup(&t->ctx, t->stack_top, &coro_start, t);

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

    // If another coroutine is waiting for this one to finish then signal it
    if (t->waiter) {
        ev_async_send(t->owner->_loop, &t->waiter->async);
    }

    t->state = TASK_STATE_FINISHED;

    // Hopefully this never returns from this point
    coro_swap(&t->owner->sched_ctx, &t->ctx);
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

    task = coro_zalloc(sizeof(struct coro_task));
    if (!task) {
        goto error;
    }

    if (allocate_stack(task, stack_size)) {
        goto error;
    }
    task->state = TASK_STATE_INIT;

    // Make sure this is NULL
    task->waiter = NULL;
    task->name = NULL;

    INIT_LIST_HEAD(&task->trigger_list);
    task->pending = NULL;

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

    task_remove_pending(task);

    if (task->stack) {
        munmap(task->stack, task->stack_size);
    }

    if (task->name) {
        coro_free(task->name);
    }

    coro_free(task);

    if (g_active_loop && list_empty(&g_active_loop->tasks)) {
        ev_break(g_active_loop->_loop, EVBREAK_ALL);
    }
}

static void task_remove_pending(struct coro_task *task)
{
    if (task->pending) {
        trigger_del_watcher(task->pending, task);
        task->pending = NULL;
    }
}

static int allocate_stack(struct coro_task *t, size_t size)
{
    t->stack = coro_stackalloc(size);
    if (!t->stack) {
        return -1;
    }

    t->stack_size = size;
    t->stack_top =
            (uint8_t *)((
                            (uintptr_t)t->stack + t->stack_size) & ~0xf
                        );
    return 0;
}

// Trigger Functions
static struct coro_trigger *trigger_new(struct coro_loop *loop)
{
    struct coro_trigger *trigger = coro_zalloc(sizeof(struct coro_trigger));

    assert(trigger); // Im not prepared to handle this yet

    trigger->type = CORO_NONE;
    trigger->ref_count = 1;
    trigger->loop = loop;
    INIT_LIST_HEAD(&trigger->tasks);

    return trigger;
}

static struct coro_trigger *trigger_new_async(struct coro_loop *loop)
{
    struct coro_trigger *trigger = trigger_new(loop);

    if (!trigger) {
        return NULL;
    }

    trigger->type = CORO_ASYNC;
    ev_async_init(&trigger->async, &g_sentinal);
    ev_async_start(trigger->loop->_loop, &trigger->async);
    return trigger;
}

static struct coro_trigger *trigger_new_idle(struct coro_loop *loop)
{
    struct coro_trigger *trigger = trigger_new(loop);

    if (!trigger) {
        return NULL;
    }

    trigger->type = CORO_IDLE;
    ev_idle_init(&trigger->idle, &g_sentinal);
    ev_idle_start(trigger->loop->_loop, &trigger->idle);
    return trigger;
}

static struct coro_trigger *trigger_new_timer(struct coro_loop *loop, ev_tstamp time)
{
    struct coro_trigger *trigger = trigger_new(loop);

    if (!trigger) {
        return NULL;
    }

    trigger->type = CORO_TIMER;
    ev_timer_init(&trigger->timer, &g_sentinal, time, 0);
    ev_timer_start(trigger->loop->_loop, &trigger->timer);
    return trigger;
}

static struct coro_trigger *trigger_new_io(struct coro_loop *loop, int fd, int how)
{
    struct coro_trigger *trigger;
    int events = 0;
    if (how & CORO_FD_WAIT_READ) {
        events |= EV_READ;
    }

    if (how & CORO_FD_WAIT_WRITE) {
        events |= EV_WRITE;
    }

    assert(events);

    trigger = trigger_new(loop);

    if (!trigger) {
        return NULL;
    }

    trigger->type = CORO_IO;
    ev_io_init(&trigger->io, &g_sentinal, fd, events);
    ev_io_start(trigger->loop->_loop, &trigger->io);
    return trigger;
}

static void trigger_add_watcher(struct coro_trigger *trigger, struct coro_task *task)
{
    list_add_tail(&task->trigger_list, &trigger->tasks);
    trigger_inc_ref(trigger);
}

static void trigger_del_watcher(struct coro_trigger *trigger, struct coro_task *task)
{
    (void) trigger;
    list_del_init(&task->trigger_list);
    trigger_dec_ref(trigger);
}

static void trigger_inc_ref(struct coro_trigger *trigger)
{
    trigger->ref_count++;
}

static void trigger_dec_ref(struct coro_trigger *trigger)
{
    assert(trigger->ref_count);
    trigger->ref_count--;

    if (trigger->ref_count == 0) {
        trigger_destroy(trigger);
    }
}

static void trigger_destroy(struct coro_trigger *trigger)
{
    struct ev_loop *loop;

    assert(trigger != NULL);
    assert(trigger->loop);

    loop = trigger->loop->_loop;

    switch (trigger->type) {
    case CORO_NONE:
        break;
    case CORO_IO:
        ev_io_stop(loop, &trigger->io);
        break;
    case CORO_IDLE:
        ev_idle_stop(loop, &trigger->idle);
        break;
    case CORO_ASYNC:
        ev_async_stop(loop, &trigger->async);
        break;
    case CORO_TIMER:
        ev_timer_stop(loop, &trigger->timer);
        break;
    default:
        assert(false);
    }

    coro_free(trigger);
}

static struct coro_queue_data *queue_data_build(void *data, void (*free_f)(void *))
{
    struct coro_queue_data *n = coro_zalloc(sizeof(struct coro_queue_data));

    if (n) {
        n->data = data;
        n->free_f = free_f;
    }

    return n;
}

static void queue_data_destroy(struct coro_queue_data *data)
{
    if (data->free_f) {
        data->free_f(data->data);
    }

    list_del(&data->node);

    coro_free(data);
}
