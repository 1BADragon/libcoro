
.type coro_swap_ctx, function
.global coro_swap_ctx
coro_swap_ctx:
   # collect the return address
   movq     0(%rsp), %rdx 

   # store values into the "from" ctx
   movq     %rdx, 0(%rsi)
   movq     %rsp, 8(%rsi)
   movq     %rbx, 16(%rsi)
   movq     %rbp, 24(%rsi)
   movq     %r12, 32(%rsi)
   movq     %r13, 40(%rsi)
   movq     %r14, 48(%rsi)
   movq     %r15, 56(%rsi)
   movq     %rdi, 64(%rsi)

   # load vaules from the "to" ctx
   movq     %rdi, %rsi

   movq     64(%rsi), %rdi
   movq     56(%rsi), %r15
   movq     48(%rsi), %r14
   movq     40(%rsi), %r13
   movq     32(%rsi), %r12
   movq     24(%rsi), %rbp
   movq     16(%rsi), %rbx
   movq     8(%rsi), %rsp
   movq     0(%rsi), %rsi

   jmp      *%rsi
