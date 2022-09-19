#ifndef CORO_THREAD_H
#define CORO_THREAD_H

#ifdef MULTI_THREAD
#include <stdbool.h>
#include <pthread.h>
#define THREAD_LOCAL __thread

typedef pthread_mutex_t mutex_t;

#define MTX_DECL(name) mutex_t *name

int mtx_init(mutex_t **mtx);
void mtx_deinit(mutex_t *mtx);
int mtx_lock(mutex_t *mtx);
int mtx_unlock(mutex_t *mtx);
bool mtx_alive(mutex_t *mtx);
#else
#define THREAD_LOCAL

#define MTX_DECL(...)

#define mtx_init(...) (0)
#define mtx_deinit(...)
#define mtx_lock(...) (0)
#define mtx_unlock(...) (0)
#define mtx_alive(...)(false)
#endif

#endif
