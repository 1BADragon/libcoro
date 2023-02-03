#ifndef CORO_MACRO_H
#define CORO_MACRO_H

#define __unused __attribute__((unused))

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#endif // MACRO_H
