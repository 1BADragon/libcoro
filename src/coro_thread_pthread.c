#ifdef MULTI_THREAD

#include <pthread.h>
#include <coro_thread.h>

int mtx_init(mutex_t *mtx)
{
    pthread_mutexattr_t attr = {0};

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    return pthread_mutex_init(mtx, &attr);
}

void mtx_deint(mutex_t *mtx)
{
    pthread_mutex_destroy(mtx);
}

int mtx_lock(mutex_t *mtx)
{
    return pthread_mutex_lock(mtx);
}

int mtx_unlock(mutex_t *mtx)
{
    return pthread_mutex_unlock(mtx);
}

#endif
