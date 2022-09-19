#ifndef CORO_TYPES_H
#define CORO_TYPES_H

#include <stdatomic.h>
#include <list.h>
#include <coro.h>
#include <coro_arch.h>
#include <coro_thread.h>

// Used when a timer event occurs. Not used in normal API usage
#define CORO_WAIT_TIMER (1 << 2)
// Used when an async event occurs. Not used in normal API usage
#define CORO_WAIT_ASYNC (1 << 3)
// Used when an IDLE event occurs. Not used in normal API usage
#define CORO_WAIT_IDLE (1 << 4)
// Used when a CUSTOM event watcher indicates its ready.
#define CORO_WAIT_CUSTOM (1 << 5)
// Used when a RESUME event has occured.
#define CORO_WAIT_RESUME (1 << 6)

enum coro_watcher_type {
    CORO_NONE,
    CORO_IO,
    CORO_IDLE,
    CORO_ASYNC,
    CORO_TIMER,
};

struct coro_trigger {
    void *private;
    enum coro_watcher_type type;
    struct list_head tasks;
    struct coro_loop *loop;
    unsigned int ref_count;
};

struct coro_loop {
    struct coro_backend *backend;
    struct coro_backend_type *backend_type;

    struct coro_ctx sched_ctx;
    struct coro_task *active;

    struct list_head ready_l;
    struct list_head tasks_l;
    struct list_head queues_l;
    struct list_head customs_l;
    struct list_head call_q;

    void *async_watcher;
    struct coro_trigger async_trigger;
    atomic_bool async_pending;
    int ret_code;

    bool running;
    MTX_DECL(lock);
};

struct coro_func_node {
    struct list_head node;
    union {
        coro_cleanup_f cleanup;
        coro_void_f callsoon;
    };
    void *arg;
};

struct coro_task {
    struct coro_loop *owner;
    struct list_head node;

    struct list_head trigger_list;
    struct list_head running_list;
    struct coro_trigger *pending;

    int last_revent;

    coro_task_entry_f entry;

    // input/output values for the coro
    void *arg;
    void *val;

    // Set by those who are waiting for this task
    struct coro_trigger *waiter;

    struct coro_ctx ctx;
    enum coro_task_state state;
    uint8_t *stack;
    uint8_t *stack_top;
    size_t stack_size;

    struct list_head cleanup_list;

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

    bool write_closed;
};

struct coro_custom {
    struct list_head node;
    struct coro_task *task;

    coro_wait_custom_f poll;
    void *cb_data;
};

#endif
