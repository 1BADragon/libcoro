#ifndef CORO_H
#define CORO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <sys/socket.h>

// dumb macro to help dev's note coro's
#define coro

struct coro_loop;
struct coro_task;

typedef void *(*coro_task_entry_f)(void *);

enum coro_task_wait_how {
    CORO_TASK_WAIT_FIRST,
    CORO_TASK_WAIT_ALL
};

enum coro_task_state {
    TASK_STATE_INIT,
    TASK_STATE_RUNNING,
    TASK_STATE_FINISHED
};

enum coro_fd_wait_how {
    CORO_FD_WAIT_READ,
    CORO_FD_WAIT_WRITE
};

struct coro_loop *coro_new_loop(int flags);
void coro_free_loop(struct coro_loop *l);
int coro_run(struct coro_loop *l);
struct coro_loop *coro_current(void);
struct coro_task *coro_current_task(void);

// Task building functions
struct coro_task *coro_create_task(struct coro_loop *loop,
                                   coro_task_entry_f entry, void *arg);

// Task status functions
bool coro_task_running(struct coro_task *task);
struct coro_loop *coro_task_parent(struct coro_task *task);
enum coro_task_state coro_task_state(struct coro_task *task);
int coro_task_set_name(struct coro_task *task, const char *name);
const char *coro_task_name(struct coro_task *task);

// Task destroying functions
int coro_cancel_task(struct coro_task *task);
// Wait from outside the loop
void *coro_task_join(struct coro_task *task);

// Wait from within the loop (as a coro)
// Cleans the awaited task
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
void coro_wait_fd(int fd, enum coro_fd_wait_how how);
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
