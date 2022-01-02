#include <stdlib.h>

#include <coro.h>
#include <coro_ev.h>

struct coro_loop {
    struct ev_loop *_loop;
};

struct coro_loop *coro_new(int flags)
{
    (void) flags;
    struct coro_loop *c = NULL;

    c = calloc(1, sizeof(struct coro_loop));
    if (!c) {
        goto error;
    }

    c->_loop = ev_loop_new(EVFLAG_AUTO);
    if (!c->_loop) {
        goto error;
    }

    return c;

error:
    coro_free_loop(c);
    return NULL;
}

void coro_free_loop(struct coro_loop *c)
{
    if (NULL == c) {
        return;
    }

    if (c->_loop) {
        ev_loop_destroy(c->_loop);
    }

    free(c);
}
