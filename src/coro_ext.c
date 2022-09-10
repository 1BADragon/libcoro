#ifdef _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/stat.h>

#include <coro.h>

struct _int_coro_io_ctx {
    int fd;
};

static FILE *dupopen(int fd, const char *mode);

static ssize_t _int_coro_read(void *cookie, char *buf, size_t size);
static ssize_t _int_coro_write(void *cookie, const char *buf, size_t size);
static int _int_coro_seek(void *cookie, off64_t *offset, int whence);
static int _int_coro_close(void *cookie);

static int mode_to_int(const char *mode);

FILE *coro_stdin;
FILE *coro_stdout;
FILE *coro_stderr;

static mode_t g_umask;

static cookie_io_functions_t _int_coro_io_funcs = {
    &_int_coro_read,
    &_int_coro_write,
    &_int_coro_seek,
    &_int_coro_close
};

FILE *coro_fopen(const char *path, const char *mode_str)
{
    int mode = mode_to_int(mode_str);

    if (-1 == mode) {
        errno = EINVAL;
        return NULL;
    }

    int fd = open(path, mode, g_umask);

    FILE *f = coro_fdopen(fd, mode_str);

    if (!f) {
        close(fd);
    }

    return f;
}

FILE *coro_fdopen(int fd, const char *mode)
{
    struct _int_coro_io_ctx *cookie = NULL;

    cookie = malloc(sizeof(struct _int_coro_io_ctx));
    if (NULL == cookie) {
        return NULL;
    }

    cookie->fd = fd;
    return fopencookie(cookie, mode, _int_coro_io_funcs);
}

ssize_t coro_printf(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    ssize_t ret = vfprintf(coro_stdout, fmt, args);
    va_end(args);

    fflush(coro_stdout);

    return ret;
}

__attribute__((constructor))
static void init_io_vals(void)
{
    coro_stdin = dupopen(STDIN_FILENO, "r");
    coro_stdout = dupopen(STDOUT_FILENO, "w");
    coro_stderr = dupopen(STDERR_FILENO, "w");

    umask(g_umask = umask(0777));
}

__attribute__((destructor))
static void deinit_io_vals(void)
{
    fclose(coro_stdin);
    fclose(coro_stdout);
    fclose(coro_stderr);
}

static FILE *dupopen(int fd, const char *mode)
{
    int new_fd = dup(fd);

    return coro_fdopen(new_fd, mode);
}

static ssize_t _int_coro_read(void *cookie, char *buf, size_t size)
{
    struct _int_coro_io_ctx *ctx = cookie;

    return ((coro_current()) ? coro_read : read)(ctx->fd, buf, size);
}

static ssize_t _int_coro_write(void *cookie, const char *buf, size_t size)
{
    struct _int_coro_io_ctx *ctx = cookie;

    return ((coro_current()) ? coro_write : write)(ctx->fd, buf, size);
}

static int _int_coro_seek(void *cookie, off64_t *offset, int whence)
{
    struct _int_coro_io_ctx *ctx = cookie;

    int rc = lseek(ctx->fd, *offset, whence);

    if (rc == -1) {
        return rc;
    }

    *offset = rc;
    return 0;
}

static int _int_coro_close(void *cookie)
{
    struct _int_coro_io_ctx *ctx = cookie;

    close(ctx->fd);
    ctx->fd = -1;

    free(ctx);
    return 0;
}

static int mode_to_int(const char *mode)
{
    if (!strcmp(mode, "r")) {
        return O_RDONLY;
    } else if (!strcmp(mode, "w")) {
        return O_WRONLY | O_CREAT | O_TRUNC;
    } else if (!strcmp(mode, "a")) {
        return O_WRONLY | O_CREAT | O_APPEND;
    } else if (!strcmp(mode, "r+")) {
        return O_RDWR;
    } else if (!strcmp(mode, "w+")) {
        return O_RDWR | O_CREAT | O_TRUNC;
    } else if (!strcmp(mode, "a+")) {
        return O_RDWR | O_CREAT | O_APPEND;
    }

    return -1;
}

#endif
