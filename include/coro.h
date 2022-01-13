#ifndef CORO_H
#define CORO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <sys/socket.h>

// dumb macro to help dev's note coroutines. Does not need to be used.
#define coro

/**
 * @struct coro_loop
 * @brief Coroutine loop context. Top level container for coroutines. A coro_loop contains
 * coroutine and queue contexts. Created with coro_new_loop.
 */
struct coro_loop;

/**
 * @struct coro_task
 * @brief Task object. Context for a single coroutine. Created with coro_create_task and
 * destroyed with either coro_task_join from outside a coroutine or coro_await from within
 * a coroutine.
 */
struct coro_task;

/**
 * @struct coro_queue
 * @brief Queue object. Used to pass data between coroutines. This queue is not threadsafe. It
 * is only safe to pass data between coroutines of the same loop.
 */
struct coro_queue;

/**
 * @typedef coro_task_entry_f
 * @brief Function prototype describing the signature of an entrypoint for a coroutine.
 *
 * @param arg Input argument into the coroutine. Value passed directly through.
 * @return The final return value from the coroutine.
 */
typedef void *(*coro_task_entry_f)(void *arg);

/**
 * @brief The coro_task_wait_how enum is used with coro_wait_task to indicate how to
 * wait for tasks to complete.
 */
enum coro_task_wait_how {
    /// Wait for any one task to complete
    CORO_TASK_WAIT_FIRST,
    /// Wait for all tasks to complete
    CORO_TASK_WAIT_ALL
};

/**
 * @brief The coro_task_state enum indicates the current task running state.
 */
enum coro_task_state {
    /// A task has been created but not started.
    TASK_STATE_INIT,
    /// A task has been started. This is the state of a task until it's entry point returns.
    TASK_STATE_RUNNING,
    /// A task has been finished.
    TASK_STATE_FINISHED
};

/**
 * @macro CORO_FD_WAIT_READ
 * @brief Used to inform coro_wait_fd to wait for a read event to occur on the provided fd.
 */
#define CORO_FD_WAIT_READ   0x01

/**
 * @macro CORO_FD_WAIT_WRITE
 * @brief Used to inform coro_wait_fd to wait for a write event to occur on the provided fd.
 */
#define CORO_FD_WAIT_WRITE  0x02

/**
 * @brief Create a new coroutine loop. It is safe to create more than one coroutine loop as
 * long as coro_run is only once per thread.
 * @param flags Currently unused and should be set to 0. May have use in the future.
 * @return A pointer to a new loop ctx or NULL if an error occured.
 */
struct coro_loop *coro_new_loop(int flags);

/**
 * @brief Frees all data associated with a coroutine loop. Not safe to call while the loop is
 * running.
 * @param l The loop context to free.
 */
void coro_free_loop(struct coro_loop *l);

/**
 * @brief Start running a coroutine loop. Loop wil continue running until all tasks have
 * either been completed or cancelled.
 * @param l The loop context.
 * @return Will return -1 if the loop could not be started. Typically means a different loop
 * is already running.
 */
int coro_run(struct coro_loop *l);

/**
 * @brief Returns the currently running loop.
 * @return Null if not in loop.
 */
struct coro_loop *coro_current(void);

/**
 * @brief Returns the currently running task.
 * @return Null if not in loop.
 */
struct coro_task *coro_current_task(void);

// Task building functions
/**
 * @brief Build a new task and queues it for execution.
 * @param loop Owning loop can be NULL if called from within a running coroutine, new task will
 * be bound to the passed in loop.
 * @param entry Entry point for the coroutine.
 * @param arg Passed in argument.
 * @return New coroutine context or NULL on error.
 */
struct coro_task *coro_create_task(struct coro_loop *loop,
                                   coro_task_entry_f entry, void *arg);

// Task status functions
/**
 * @brief Returns true if the provided task state is either CORO_TASK_INIT or
 * CORO_TASK_RUNNING.
 */
bool coro_task_running(struct coro_task *task);

/**
 * @brief Returns the parent loop of a provided task.
 */
struct coro_loop *coro_task_parent(struct coro_task *task);

/**
 * @brief Returns the current state of a provided task.
 */
enum coro_task_state coro_task_state(struct coro_task *task);

/**
 * @brief Set the name of a task.
 * @param task Task context to name.
 * @param name A pointer to a NULL-terminated C string. This data is coppied.
 * @return 0 on success otherwise errno is set.
 */
int coro_task_set_name(struct coro_task *task, const char *name);

/**
 * @brief Returns the name of a given task. If the task was never named this will return NULL.
 */
const char *coro_task_name(struct coro_task *task);

// Task destroying functions
/**
 * @brief Cancels and destroys a coroutine context. This should not be called from the active
 * task. Can be called from either within or outside of a coroutine loop.
 */
int coro_cancel_task(struct coro_task *task);
// Wait from outside the loop
/**
 * @brief Collects the return result of a completed coroutine and frees the coroutine's data. Will
 * return NULL if the task is not completed yet.
 */
void *coro_task_join(struct coro_task *task);

// Queue functions
/**
 * @brief Builds a new queue that can be used from withing a provided loops coroutines. If called
 * from within a running coroutine then loop can be NULL.
 */
struct coro_queue *coro_queue_new(struct coro_loop *loop);

/**
 * @brief Destroys a queue and frees any pending data.
 */
void coro_queue_delete(struct coro_queue *queue);

/**
 * @brief Push new data to the coro queue. An optional free function can be provided to
 * clean any pending data when the queue is destoryed.
 */
int coro_queue_push(struct coro_queue *queue, void *data, void (*free_f)(void *));

/**
 * @brief Pop data from the queue. Will block and yeild if no data is available on the queue. Will
 * return NULL if the queue is destoryed.
 *
 * @note Currently only one coroutine can wait for data at a time.
 */
void *coro_queue_pop(struct coro_queue *queue);

/**
 * @brief Pop data form the queue without waiting for data if non is available. Will return
 * NULL if no data is available.
 *
 * @warning Be careful for use-after-free errors.
 */
void *coro_queue_pop_nowait(struct coro_queue *queue);

// Wait from within the loop (as a coro)
// Cleans the awaited task
/**
 * @brief Waits for a task to complete and returns the return value from the coroutine. Can only
 * be called from within a running coroutine.
 */
void *coro_await(struct coro_task *task);

// Coro yeilding and IO functions
// Generic yeild, resumes after swapping to the scheduler
void coro_yeild();

// Does not clean the awaited tasks so user can determine what to do
void coro_wait_tasks(struct coro_task **task, size_t len, enum coro_task_wait_how how);

// Sleeping functions
void coro_sleep(unsigned long amnt);
void coro_sleepms(unsigned long amnt);

// Basic IO functions
void coro_wait_fd(int fd, int how);
long coro_read(int fd, void *buf, unsigned long len);
long coro_write(int fd, const void *buf, unsigned long len);

int coro_accept(int sock, struct sockaddr *addr, socklen_t *addr_len);
long coro_recv(int sock, void *buf, unsigned long len, int flags);
long coro_recvfrom(int sock, void *restrict buf, unsigned long len,
                   int flags, struct sockaddr *restrict src_addr,
                   socklen_t *restrict addrlen);
long coro_recvmsg(int sock, struct msghdr *msg, int flags);
long coro_send(int sock, const void *buf, unsigned long len, int flags);
long coro_sendto(int sock, const void *buf, unsigned long len, int flags,
                 const struct sockaddr *dest_addr, socklen_t addrlen);
long coro_sendmsg(int sockfd, const struct msghdr *msg, int flags);

// Coro hook functions
void coro_hook_set_alloc(void *(*func)(long));
void *coro_alloc(long size);
void *coro_zalloc(long size);

void coro_hook_set_free(void (*func)(void *));
void coro_free(void *ptr);

void coro_hook_set_realloc(void *(*func)(void *, unsigned long));
void *coro_realloc(void *ptr, long s);

void coro_hook_set_stacksize(long (*func)(void));
long coro_stacksize(void);

void coro_hook_set_stackalloc(void *(*func)(unsigned long));
void *coro_stackalloc(unsigned long size);

void coro_hook_set_stackunalloc(void (*func)(void *, unsigned long));
void coro_stackunalloc(void *ptr, unsigned long size);

#endif // CORO_H
