#include <sys/user.h>

inline long long
syscall_op(struct user_regs_struct &regs) { return regs.orig_rax; }
inline long long
syscall_rc(struct user_regs_struct &regs) { return regs.rax; }
inline long long
syscall_arg0(struct user_regs_struct &regs) { return regs.rdi; }
inline long long
syscall_arg1(struct user_regs_struct &regs) { return regs.rsi; }
inline long long
syscall_arg2(struct user_regs_struct &regs) { return regs.rdx; }
inline long long
syscall_arg3(struct user_regs_struct &regs) { return regs.r10; }
inline long long
syscall_arg4(struct user_regs_struct &regs) { return regs.r8; }
inline long long
syscall_arg5(struct user_regs_struct &regs) { return regs.r9; }

#define OP (syscall_op(regs))
#define RC (syscall_rc(regs))
#define ARG0 (syscall_arg0(regs))
#define ARG1 (syscall_arg1(regs))
#define ARG2 (syscall_arg2(regs))
#define ARG3 (syscall_arg3(regs))
#define ARG4 (syscall_arg4(regs))
#define ARG5 (syscall_arg5(regs))
