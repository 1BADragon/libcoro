#ifdef MULTI_THREAD

#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <coro_thread.h>

int mtx_init(mutex_t **mtx)
{
    if (NULL == mtx) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutexattr_t attr = {0};

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    *mtx = malloc(sizeof(pthread_mutex_t));
    if (NULL == *mtx) {
        return -1;
    }

    return pthread_mutex_init(*mtx, &attr);
}

void mtx_deinit(mutex_t *mtx)
{
    pthread_mutex_destroy(mtx);
    free(mtx);
}

int mtx_lock(mutex_t *mtx)
{
    return pthread_mutex_lock(mtx);
}

int mtx_unlock(mutex_t *mtx)
{
    return pthread_mutex_unlock(mtx);
}

bool mtx_alive(mutex_t *mtx)
{
    return mtx != NULL;
}

#endif
