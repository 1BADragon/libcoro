#include <stdlib.h>

#include <ev.h>

#include <coro.h>

struct coro {
    struct ev_loop *_loop;
};

struct coro *coro_new(int flags)
{
    (void) flags;
    struct coro *c = NULL;

    c = calloc(1, sizeof(struct coro));
    if (!c) {
        goto error;
    }

    c->_loop = ev_loop_new(EVFLAG_AUTO);
    if (!c->_loop) {
        goto error;
    }

    return c;

error:
    coro_free(c);
    return NULL;
}

void coro_free(struct coro *c)
{
    free(c);
}
