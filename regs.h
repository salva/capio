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

#define AFD(arg) ((int32_t)(arg))
#define AFD0 AFD(ARG0)
#define AFD1 AFD(ARG1)
#define AFD2 AFD(ARG2)
#define RCFD AFD(RC)

static std::string
fd2string(long long arg) {
    int fd = AFD(arg);
    if (fd == -100) // AT_FDCWD = -100
        return "AT_FDCWD|" + std::to_string(fd);
    else
        return std::to_string(fd);
}

#define SAFD(arg) (fd2string(arg).c_str())
#define SAFD0 SAFD(ARG0)
#define SAFD1 SAFD(ARG1)
#define SAFD2 SAFD(ARG2)
#define SAFD4 SAFD(ARG4)

