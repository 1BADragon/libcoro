#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

#include <list.h>
#include <coro.h>
#include <coro_ctx.h>
#include <coro_types.h>
#include <coro_arch.h>
#include <coro_thread.h>
#include <backends/coro_backend.h>

static THREAD_LOCAL struct coro_loop *g_active_loop;

static void loop_async_callback(struct coro_trigger *trigger);
static void coro_maintenance(struct coro_loop *loop);

static int process_call_queue(struct coro_loop *loop);
static void process_ready_list(struct coro_loop *loop);
static void check_custom_watchers(struct coro_loop *loop);
static bool coro_should_exit(struct coro_loop *loop);
static int coro_event_trigger(struct coro_task *t);

static int coro_event_queue(struct coro_task *t, int revent);
static void coro_swap_to_sched(void);
static void coro_swap_from_sched(struct coro_task *t);
static void coro_start(struct coro_task *t);
static void coro_swap(struct coro_ctx *in, struct coro_ctx *out);

// Task functions
static struct coro_task *task_new(size_t stack_size);
static void task_trigger_waiters(struct coro_task *task);
static void task_free(struct coro_task *task);
static void task_remove_pending(struct coro_task *task);
static int allocate_stack(struct coro_task *t, size_t size);
static void task_cleanup(struct coro_task *t, enum coro_exit_how how);

// Trigger Functions
static struct coro_trigger *trigger_new(struct coro_loop *loop);
static struct coro_trigger *trigger_new_async(struct coro_loop *loop);
static struct coro_trigger *trigger_new_timer(struct coro_loop *loop, uintmax_t time);
static struct coro_trigger *trigger_new_io(struct coro_loop *loop, int fd, int how);

static void async_triggered(struct coro_trigger *trigger);
static void timer_triggered(struct coro_trigger *trigger);
static void io_triggered(struct coro_trigger *trigger, int revents);

static void triggered(struct coro_trigger *trigger, int revents);

static void trigger_add_watcher(struct coro_trigger *trigger, struct coro_task *task);
static void trigger_del_watcher(struct coro_trigger *trigger, struct coro_task *task);
static void trigger_inc_ref(struct coro_trigger *trigger);
static void trigger_dec_ref(struct coro_trigger **trigger);
static void trigger_destroy(struct coro_trigger *trigger);

// Queue helpers
static struct coro_queue_data *queue_data_build(void *data, void (*)(void *));
static void queue_data_destroy(struct coro_queue_data *data, bool should_free);

struct coro_loop *coro_new_loop(int flags)
{
    (void) flags;
    struct coro_loop *c = NULL;

    c = coro_zalloc(sizeof(struct coro_loop));
    if (!c) {
        goto error;
    }

    c->backend_type = coro_select_backend(flags);
    c->backend = c->backend_type->backend_new(flags);
    if (!c->backend) {
        goto error;
    }

    c->async_trigger.private = c;
    c->async_watcher = c->backend_type->new_async(c->backend, &loop_async_callback, &c->async_trigger);

    c->active = NULL;
    INIT_LIST_HEAD(&c->ready_l);
    INIT_LIST_HEAD(&c->tasks_l);
    INIT_LIST_HEAD(&c->queues_l);
    INIT_LIST_HEAD(&c->customs_l);
    INIT_LIST_HEAD(&c->call_q);

    c->running = false;

    if (mtx_init(&c->lock)) {
        goto error;
    }

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

    list_for_each_entry_safe(curr_task, _safe_task, &c->tasks_l, node) {
        if (TASK_STATE_RUNNING == curr_task->state) {
            task_cleanup(curr_task, TASK_EXIT_CANCELLED);
        }
        task_free(curr_task);
    }

    list_for_each_entry_safe(curr_queue, _safe_queue, &c->queues_l, node) {
        coro_queue_delete(curr_queue);
    }

    c->backend_type->free_async(c->async_watcher);

    if (c->backend) {
        c->backend_type->backend_free(c->backend);
    }

    if (mtx_alive(c->lock)) {
        mtx_deinit(c->lock);
    }

    coro_free(c);
}

int coro_run(struct coro_loop *l)
{
    if (g_active_loop) {
        return -1;
    }

    if (l->running) {
        errno = EINVAL;
        return -1;
    }

    g_active_loop = l;
    l->running = true;
    l->backend_type->backend_start(l->backend);
    l->running = false;
    g_active_loop = NULL;

    return 0;
}

int coro_poke(struct coro_loop *l)
{
    bool b = false;

    if (atomic_compare_exchange_strong(&l->async_pending, &b, true)) {
        l->backend_type->trigger_async(l->async_watcher);
    }

    return 0;
}

struct coro_loop *coro_current(void)
{
    return g_active_loop;
}

int coro_callsoon(struct coro_loop *l, coro_void_f func, void *cb_data)
{
    if (NULL == l) {
        l = coro_current();

        if (NULL == l) {
            errno = EINVAL;
            return -1;
        }
    }

    struct coro_func_node *node = coro_zalloc(sizeof(struct coro_func_node));

    if (NULL == node) {
        return -1;
    }

    node->callsoon = func;
    node->arg = cb_data;

    list_add_tail(&node->node, &l->call_q);
    coro_poke(l);
    return 0;
}

int coro_callsoon_threadsafe(struct coro_loop *l, coro_void_f func, void *cb_data)
{
    int rc = -1;

    if (NULL == l) {
        l = coro_current();

        if (NULL == l) {
            errno = EINVAL;
            return -1;
        }
    }

    if (mtx_lock(l->lock)) {
        goto EXIT;
    }

    rc = coro_callsoon(l, func, cb_data);

    if (mtx_unlock(l->lock)) {
        rc = -1;
    }

EXIT:
    return rc;
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

    task = task_new(coro_stacksize());

    if (!task) {
        return NULL;
    }

    task->entry = entry;
    task->arg = arg;
    task->owner = loop;

    list_add_tail(&task->node, &loop->tasks_l);
    if (coro_event_queue(task, CORO_WAIT_RESUME)) {
        task_free(task);
        task = NULL;
    }

    return task;
}

bool coro_task_running(struct coro_task *task)
{
    return coro_task_state(task) == TASK_STATE_INIT ||
            coro_task_state(task) == TASK_STATE_RUNNING;
}

struct coro_loop *coro_task_parent(struct coro_task *task)
{
    assert(task);
    return task->owner;
}

enum coro_task_state coro_task_state(struct coro_task *task)
{
    assert(task);
    return task->state;
}

int coro_register_cleanup(struct coro_task *task, coro_cleanup_f func, void *arg)
{
    struct coro_func_node *node = NULL;

    if (NULL == task) {
        task = coro_current_task();

        if (NULL == task) {
            errno = EINVAL;
            return -1;
        }
    }

    node = coro_zalloc(sizeof(struct coro_func_node));
    if (NULL == node) {
        return -1;
    }

    node->cleanup = func;
    node->arg = arg;

    list_add_tail(&node->node, &task->cleanup_list);
    return 0;
}

int coro_task_set_name(struct coro_task *task, const char *name)
{
    if (NULL == task) {
        task = coro_current_task();

        if (NULL == task) {
            errno = EINVAL;
            return -1;
        }
    }

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

    task_cleanup(task, TASK_EXIT_CANCELLED);

    task_free(task);
    return 0;
}

void *coro_task_join(struct coro_task *task)
{
    void *ret;

    assert(coro_current_task() != task);

    if (coro_task_running(task)) {
        return NULL;
    }

    ret = task->val;
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
    new_queue->sig = trigger_new_async(loop);

    if (!new_queue->sig) {
        goto error;
    }

    INIT_LIST_HEAD(&new_queue->data);
    list_add_tail(&new_queue->node, &loop->queues_l);
    new_queue->write_closed = false;
    return new_queue;

error:
    coro_queue_delete(new_queue);
    return NULL;
}

void coro_queue_delete(struct coro_queue *queue)
{
    struct coro_queue_data *data;
    struct coro_queue_data *_safe_data;

    if (NULL == queue) {
        return;
    }

    list_for_each_entry_safe(data, _safe_data, &queue->data, node) {
        queue_data_destroy(data, true);
    }

    trigger_dec_ref(&queue->sig);

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
    queue->parent->backend_type->trigger_async(queue->sig->private);
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

    for (;;) {
        ret = coro_queue_pop_nowait(queue);
        if (ret) {
            return ret;
        }

        if (queue->write_closed) {
            return NULL;
        }

        trigger_add_watcher(queue->sig, curr_task);
        coro_swap_to_sched();
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

    queue_data_destroy(data, false);
    return ptr;
}

void coro_queue_closewrite(struct coro_queue *queue)
{
    queue->write_closed = true;
    queue->parent->backend_type->trigger_async(queue->sig->private);
}

void *coro_await(struct coro_task *task)
{
    void *val;
    coro_await_val(task, &val);

    return val;
}

bool coro_await_val(struct coro_task *task, void **val_p)
{
    bool ret = false;
    coro_wait_tasks(&task, 1, CORO_TASK_WAIT_ALL);
    *val_p = task->val;

    if (coro_task_state(task) == TASK_STATE_YEILDING) {
        task->val = NULL;
        task->state = TASK_STATE_RUNNING;
        coro_event_queue(task, CORO_WAIT_RESUME);
    } else if (coro_task_state(task) == TASK_STATE_FINISHED) {
        task_free(task);
        ret = true;
    } else {
        assert(0);
    }

    return ret;
}

void coro_yeild()
{
    struct coro_task *_curr_task;

    _curr_task = coro_current_task();
    assert(_curr_task != NULL);

    coro_event_queue(_curr_task, CORO_WAIT_RESUME);
    coro_swap_to_sched();
}

void coro_yeild_val(void *val)
{
    struct coro_task *_curr_task;

    _curr_task = coro_current_task();

    assert(_curr_task != NULL);

    _curr_task->val = val;
    _curr_task->state = TASK_STATE_YEILDING;

    task_trigger_waiters(_curr_task);
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

    do {
        int count = 0;
        one_running = false;

        for (size_t i = 0; i < len; ++i) {
            if (coro_task_running(task[i])) {
                assert(_curr_task->owner == g_active_loop);
                assert(task[i]->waiter == trigger || task[i]->waiter == NULL);
                count++;
                task[i]->waiter = trigger;
                one_running = true;
            }
        }

        if (one_running && CORO_TASK_WAIT_FIRST != how) {
            trigger_add_watcher(trigger, _curr_task);
            coro_swap_to_sched();
        }

    } while (one_running && CORO_TASK_WAIT_FIRST != how);

    // Set all waiters back to NULL
    for (size_t i = 0; i < len; ++i) {
        task[i]->waiter = NULL;
    }

    trigger_dec_ref(&trigger);
}

void coro_sleep(uintmax_t amnt)
{
    coro_sleepms(amnt * 1000);
}

void coro_sleepms(uintmax_t amnt)
{
    struct coro_trigger *trigger;

    assert(coro_current_task());

    trigger = trigger_new_timer(g_active_loop, amnt);
    assert(trigger);
    trigger_add_watcher(trigger, coro_current_task());
    trigger_dec_ref(&trigger);
    coro_swap_to_sched();
}

void coro_wait_custom(coro_wait_custom_f poll, void *cb_data)
{
    struct coro_custom *custom;
    struct coro_loop *loop;
    struct coro_task *this;

    loop = coro_current();
    assert(loop);

    this = coro_current_task();
    assert(this);

    custom = coro_zalloc(sizeof(struct coro_custom));
    assert(custom);
    custom->task = this;
    custom->poll = poll;
    custom->cb_data = cb_data;

    list_add_tail(&custom->node, &loop->customs_l);
    coro_poke(loop);
    coro_swap_to_sched();
}

void coro_wait_fd(int fd, int how)
{
    struct coro_trigger *trigger;

    assert(coro_current());
    assert(coro_current_task());

    trigger = trigger_new_io(coro_current(), fd, how);
    trigger_add_watcher(trigger, coro_current_task());
    trigger_dec_ref(&trigger);
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

/**********************
 * Internal Functions *
 *********************/

static void loop_async_callback(struct coro_trigger *trigger)
{
    bool b = true;
    struct coro_loop *loop = trigger->private;

    if (atomic_compare_exchange_weak(&loop->async_pending, &b, false)) {
        coro_maintenance(loop);
    }
}

static void coro_maintenance(struct coro_loop *loop)
{
    process_call_queue(loop);
    check_custom_watchers(loop);    
    process_ready_list(loop);

    if (coro_should_exit(loop)) {
        loop->backend_type->backend_stop(loop->backend);
    }
}

static void process_ready_list(struct coro_loop *loop)
{
    struct coro_task *at;
    struct coro_task *_safe;
    struct list_head copy;

    if (!list_empty(&loop->ready_l)) {
        list_cut_before(&copy, &loop->ready_l, &loop->ready_l);

        list_for_each_entry_safe(at, _safe, &copy, running_list)
        {
            // Remove the list's running queued status so it can re-queue
            list_del_init(&at->running_list);
            coro_event_trigger(at);
        }

        coro_poke(loop);
    }
}

static int process_call_queue(struct coro_loop *loop)
{
    struct coro_func_node *at;
    struct coro_func_node *_safe;

    if (mtx_lock(loop->lock)) {
        return -1;
    }

    if (!list_empty(&loop->call_q)) {
        list_for_each_entry_safe(at, _safe, &loop->call_q, node) {
            at->callsoon(at->arg);

            list_del(&at->node);
            free(at);
        }

        coro_poke(loop);
    }

    return mtx_unlock(loop->lock);
}

static void check_custom_watchers(struct coro_loop *loop)
{
    struct coro_custom *at;
    struct coro_custom *safe;

    struct list_head copy;
    INIT_LIST_HEAD(&copy);

    list_cut_before(&copy, &loop->customs_l, &loop->customs_l);

    list_for_each_entry_safe(at, safe, &copy, node) {
        // either way this will be removed from this list
        list_del(&at->node);

        if (!at->poll(at->cb_data)) {
            // The task is ready
            coro_event_queue(at->task, CORO_WAIT_CUSTOM);
            free(at);
        } else {
            // The task is not ready place it on the real list
            list_add_tail(&at->node, &loop->customs_l);
        }
    }
}

static bool coro_should_exit(struct coro_loop *loop)
{
    struct coro_task *task;
    bool tasks_running = false;

    list_for_each_entry(task, &loop->tasks_l, node) {
        if (coro_task_running(task)) {
            tasks_running = true;
        }
    }

    return !tasks_running;
}

static int coro_event_trigger(struct coro_task *t)
{
    // called directly
    switch(coro_task_state(t)) {
    case TASK_STATE_INIT:
        // set the required values
        coro_ctx_setup(&t->ctx, t->stack_top, &coro_start, t);

        // transfer execution to the coro
        coro_swap_from_sched(t);
        break;
    case TASK_STATE_RUNNING:
        // Resume execution in the coro
        coro_swap_from_sched(t);
        break;
    case TASK_STATE_YEILDING:
        // A yeilding task should not have a trigger associated with it
        assert(0);
        return -1;
    case TASK_STATE_FINISHED:
        // This might be a stale watcher, this also
        // might be an error state
        break;
    }

    t->last_revent = 0;

    return 0;
}

static int coro_event_queue(struct coro_task *t, int revent)
{
    assert(t);
    assert(t->owner);

    t->last_revent |= revent;
    if (list_empty(&t->running_list)) {
        list_add_tail(&t->running_list, &t->owner->ready_l);
    }
    coro_poke(t->owner);
    return 0;
}

static void coro_swap_to_sched()
{
    // Can only be called from a coroutine
    assert(g_active_loop->active);

    // store the active coroutine on stack
    struct coro_task *t = g_active_loop->active;

    // Set active to be the scheduler
    g_active_loop->active = NULL;
    coro_swap(&g_active_loop->sched_ctx, &t->ctx);

    // restore the active back to the old active
    g_active_loop->active = t;
}

static void coro_swap_from_sched(struct coro_task *t)
{
    // This should only be called by the scheduler (active == NULL)
    assert(g_active_loop->active == NULL);
    // Set t as the active coro
    g_active_loop->active = t;
    // Swap into the new coroutine
    coro_swap(&t->ctx, &t->owner->sched_ctx);

    // Upon return unset active coro as this code should only execut by the scheduler
    g_active_loop->active = NULL;
}

static void coro_start(struct coro_task *t)
{
    g_active_loop->active = t;
    t->state = TASK_STATE_RUNNING;

    // call the coroutine entry
    t->val = t->entry(t->arg);

    task_cleanup(t, TASK_EXIT_NORMAL);

    // If another coroutine is waiting for this one to finish then signal it
    task_trigger_waiters(t);

    t->state = TASK_STATE_FINISHED;

    // Hopefully this never returns from this point
    coro_swap_to_sched();
    assert(0);
}

static void coro_swap(struct coro_ctx *in, struct coro_ctx *out)
{
    // printf("Swap in %p out %p\n", in, out);
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

    INIT_LIST_HEAD(&task->cleanup_list);

    // Running list node should be initialized
    INIT_LIST_HEAD(&task->running_list);

    return task;
error:
    task_free(task);
    return NULL;
}

static void task_trigger_waiters(struct coro_task *task)
{
    if (task->waiter) {
        task->owner->backend_type->trigger_async(task->waiter->private);
    }
}

static void task_free(struct coro_task *task)
{
    if (!task) {
        return;
    }

    assert(list_empty(&task->cleanup_list));

    list_del(&task->node);
    list_del(&task->running_list);

    task_remove_pending(task);

    if (task->stack) {
        munmap(task->stack, task->stack_size);
    }

    if (task->name) {
        coro_free(task->name);
    }

    if (task->pending) {
        list_del(&task->trigger_list);
        task->pending = NULL;
    }

    if (task->owner && list_empty(&task->owner->tasks_l)) {
        task->owner->backend_type->backend_stop(task->owner->backend);
    }

    coro_free(task);
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

static void task_cleanup(struct coro_task *t, enum coro_exit_how how)
{
    struct coro_func_node *at;
    struct coro_func_node *_safe;

    list_for_each_entry_safe(at, _safe, &t->cleanup_list, node) {
        at->cleanup(how, at->arg);

        list_del(&at->node);
        coro_free(at);
    }
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
    trigger->private = loop->backend_type->new_async(loop->backend, &async_triggered, trigger);
    if (!trigger->private) {
        trigger_destroy(trigger);
        return NULL;
    }

    return trigger;
}

static struct coro_trigger *trigger_new_timer(struct coro_loop *loop, uintmax_t time_ms)
{
    struct coro_trigger *trigger = trigger_new(loop);

    if (!trigger) {
        return NULL;
    }

    trigger->type = CORO_TIMER;
    trigger->private = loop->backend_type->new_timer(loop->backend, &timer_triggered,
                                                     trigger, time_ms);
    return trigger;
}

static struct coro_trigger *trigger_new_io(struct coro_loop *loop, int fd, int how)
{
    struct coro_trigger *trigger;

    assert(how);

    trigger = trigger_new(loop);

    if (!trigger) {
        return NULL;
    }

    trigger->type = CORO_IO;
    trigger->private = loop->backend_type->new_io(loop->backend, &io_triggered, trigger, fd, how);
    return trigger;
}

static void async_triggered(struct coro_trigger *trigger)
{
    triggered(trigger, CORO_WAIT_ASYNC);
}

static void timer_triggered(struct coro_trigger *trigger)
{
    triggered(trigger, CORO_WAIT_TIMER);
}

static void io_triggered(struct coro_trigger *trigger, int revents)
{
    triggered(trigger, revents);
}

static void triggered(struct coro_trigger *trigger, int revents)
{
    struct coro_task *task;
    struct coro_task *_safe;

    // increment trigger to prevent it from being deleted while traversing the loop
    trigger_inc_ref(trigger);

    // Create a copy of the old list and clear the exsiting
    struct list_head tmp_list = trigger->tasks;
    list_cut_before(&tmp_list, &trigger->tasks, &trigger->tasks);

    INIT_LIST_HEAD(&trigger->tasks);

    list_for_each_entry_safe(task, _safe, &tmp_list, trigger_list) {
        trigger_del_watcher(trigger, task);
        coro_event_queue(task, revents);
    }

    trigger_dec_ref(&trigger);
}

static void trigger_add_watcher(struct coro_trigger *trigger, struct coro_task *task)
{
    assert(task->pending == NULL);
    task->pending = trigger;
    list_add_tail(&task->trigger_list, &trigger->tasks);
    trigger_inc_ref(trigger);
}

static void trigger_del_watcher(struct coro_trigger *trigger, struct coro_task *task)
{
    assert(task->pending == trigger);
    list_del_init(&task->trigger_list);
    trigger_dec_ref(&trigger);
    task->pending = NULL;
}

static void trigger_inc_ref(struct coro_trigger *trigger)
{
    trigger->ref_count++;
}

static void trigger_dec_ref(struct coro_trigger **trigger)
{
    assert((*trigger)->ref_count);
    (*trigger)->ref_count--;

    if ((*trigger)->ref_count == 0) {
        trigger_destroy(*trigger);
    }

    *trigger = NULL;
}

static void trigger_destroy(struct coro_trigger *trigger)
{
    struct coro_backend_type *type;

    assert(trigger != NULL);
    assert(trigger->loop);

    type = trigger->loop->backend_type;

    switch (trigger->type) {
    case CORO_NONE:
        break;
    case CORO_IO:
        type->free_io(trigger->private);
        break;
    case CORO_IDLE:
        type->free_idle(trigger->private);
        break;
    case CORO_ASYNC:
        type->free_async(trigger->private);
        break;
    case CORO_TIMER:
        type->free_timer(trigger->private);
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

static void queue_data_destroy(struct coro_queue_data *data, bool should_free)
{
    if (data->free_f && should_free) {
        data->free_f(data->data);
    }

    list_del(&data->node);

    coro_free(data);
}
