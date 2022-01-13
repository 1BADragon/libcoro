#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <coro.h>

static void *reader(void *data)
{
    int rc;
    char c;
    int fd = *(int *)data;

    for (;;) {
        rc = coro_read(fd, &c, 1);

        if (rc <= 0) {
            break;
        }

        putc(c, stdout);
        fflush(stdout);
    }

    close(fd);

    return NULL;
}

static void *writer(void *data)
{
    const char *message = "This is a test message!!!\n";

    for (size_t i = 0; i < strlen(message); ++i) {
        coro_write(*(int *)data, &message[i], 1);
        coro_sleepms(10);
    }

    close(*(int *)data);

    return NULL;
}

int main()
{
    int fd[2];

    pipe2(fd, O_NONBLOCK);

    struct coro_loop *loop = coro_new_loop(0);

    struct coro_task *rt = coro_create_task(loop, reader, &fd[0]);
    struct coro_task *wt = coro_create_task(loop, writer, &fd[1]);

    coro_run(loop);
    coro_task_join(rt);
    coro_task_join(wt);

    coro_free_loop(loop);

    return 0;
}
