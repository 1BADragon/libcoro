#ifndef CORO_TYPES_H
#define CORO_TYPES_H

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

struct coro_loop {
    struct coro_backend *backend;
    struct coro_backend_type *backend_type;

    struct coro_ctx sched_ctx;
    struct coro_task *active;

    struct list_head tasks;
    struct list_head queues;

    struct list_head customs;

    bool running;

    MTX_DECL(lock);
    bool lock_init;
};

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

struct coro_func_node {
    struct list_head node;
    coro_cleanup_f func;
    void *arg;
};

struct coro_task {
    struct coro_loop *owner;
    struct list_head node;

    struct list_head trigger_list;
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
