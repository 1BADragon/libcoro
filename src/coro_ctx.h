/**
 * @file coro_ctx.h
 * @brief Header file for architecture specific declarations.
 */

#ifndef CORO_CTX_H
#define CORO_CTX_H

/**
 * @struct coro_ctx
 * @brief Stores execution context information. This struct is implemented on a per architecture
 * basis. The defined structure requires 2 feilds pc, and sp for the program counter and stack
 * pointer values, respectively. This values must be available to set from the core coro
 * code.
 */
struct coro_ctx;

/**
 * @brief Used to store and arg1 value at startup. This function is called once per
 * coroutine, at the start of the routine. I will require the arch specific code to set
 * the first argument of a calling context.
 */
void coro_ctx_setup(struct coro_ctx *ctx, void *stack, void *entry, void *val);

/**
 * @brief Swaps execution context between to and from, Current exectuion is stored in "to" and
 * an existing execution context is loaded from "from". This function needs to be defined on a
 * per architecture basis. A linux-generic version of this can probably be implemented with
 * ucontext but initally this was a learning project so it was implemented in assembly.
 * @param to The Context to swap into to. This function will return from this context.
 * @param from The Context being swapped from. The calling context is stored in "from"
 */
void coro_swap_ctx(struct coro_ctx *to, struct coro_ctx *from);

#endif // CORO_CTX_H
