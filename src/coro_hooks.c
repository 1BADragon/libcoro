#include <stdlib.h>
#include <string.h>
#include <coro.h>

#include <sys/mman.h>

#define PAGE_SIZE (4096)
#define DEFAULT_STACK_SIZE (PAGE_SIZE * 6)

static void *coro_alloc_def(long size);
static void coro_free_def(void *ptr);
static void *coro_realloc_def(void *ptr, unsigned long size);
static long coro_stacksize_def(void);
static void *coro_stackalloc_def(unsigned long size);
static void coro_stackunalloc_def(void *ptr, unsigned long size);

static void *(*coro_alloc_f)(long) = coro_alloc_def;
static void (*coro_free_f)(void *) = coro_free_def;
static void *(*coro_realloc_f)(void *, unsigned long) = coro_realloc_def;
static long (*coro_stacksize_f)(void) = coro_stacksize_def;
static void *(*coro_stackalloc_f)(unsigned long size) = coro_stackalloc_def;
static void (*coro_stackunalloc_f)(void *ptr, unsigned long size) = coro_stackunalloc_def;

void coro_hook_set_alloc(void *(*func)(long))
{
    coro_alloc_f = func;
}

void *coro_alloc(long size)
{
    if (coro_alloc_f) {
        return coro_alloc_f(size);
    }

    return coro_alloc_def(size);
}

void *coro_zalloc(long size)
{
    void *mem = coro_alloc(size);

    if (mem) {
        memset(mem, 0, size);
    }
    return mem;
}

void coro_hook_set_free(void (*func)(void *))
{
    coro_free_f = func;
}

void coro_free(void *ptr)
{
    if (coro_free_f) {
        coro_free_f(ptr);
        return;
    }

    coro_free_def(ptr);
}

void coro_hook_set_realloc(void *(*func)(void *, unsigned long))
{
    coro_realloc_f = func;
}

void *coro_realloc(void *ptr, long s)
{
    if (coro_realloc_f) {
        return coro_realloc_f(ptr, s);
    }

    return coro_realloc_def(ptr, s);
}

void coro_hook_set_stacksize(long (*func)(void))
{
    coro_stacksize_f = func;
}

long coro_stacksize(void)
{
    if (coro_stacksize_f) {
        return coro_stacksize_f();
    }

    return coro_stacksize_def();
}

void coro_hook_set_stackalloc(void *(*func)(unsigned long))
{
    coro_stackalloc_f = func;
}

void *coro_stackalloc(unsigned long size)
{
    if (coro_stackalloc_f) {
        return coro_stackalloc_f(size);
    }

    return coro_stackalloc_def(size);
}

void coro_hook_set_stackunalloc(void (*func)(void *, unsigned long))
{
    coro_stackunalloc_f = func;
}

void coro_stackunalloc(void *ptr, unsigned long size)
{
    if (coro_stackunalloc_f) {
        coro_stackunalloc_f(ptr, size);
    }

    return coro_stackunalloc_def(ptr, size);
}

static void *coro_alloc_def(long size)
{
    return malloc(size);
}

static void coro_free_def(void *ptr)
{
    free(ptr);
}

static void *coro_realloc_def(void *ptr, unsigned long size)
{
    if (!size) {
        free(ptr);
        return NULL;
    }

    return realloc(ptr, size);
}

static long coro_stacksize_def(void)
{
    return DEFAULT_STACK_SIZE;
}

static void *coro_stackalloc_def(unsigned long size)
{
    if (size % PAGE_SIZE) {
        size = (size + PAGE_SIZE) & ~PAGE_SIZE;
    }

    void *ptr = mmap(NULL, size + (PAGE_SIZE * 2), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (NULL == ptr) {
        return NULL;
    }

    // create protected pages to prevent stack overflow
    mprotect(ptr, PAGE_SIZE, PROT_NONE);
    mprotect(ptr + size + PAGE_SIZE, 4096, PROT_NONE);
    return ptr;
}

static void coro_stackunalloc_def(void *ptr, unsigned long size)
{
    munmap(ptr, size);
}
