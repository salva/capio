
//#include "capio.h";

struct Capio;
struct Process;
struct user_regs_struct;

typedef void (*syscall_handler)(Capio &c, Process &p, struct user_regs_struct &regs);

#define SYSCALL_UNEXPECTED 1
#define SYSCALL_READ 2
#define SYSCALL_WRITE 4
#define SYSCALL_ABI_64 8
#define SYSCALL_ABI_X32 16
#define SYSCALL_PTREGS 32

struct syscall {
    const char *name;
    int flags;
    long long groups;
    syscall_handler handler;

    bool writes() {
        return ((flags & SYSCALL_WRITE) == SYSCALL_WRITE);
    }

};

extern struct syscall syscalls[];

#define SYSCALL_UNEXPECTED 1
#define SYSCALL_READ 2
#define SYSCALL_WRITE 4
#define SYSCALL_ABI_64 8
#define SYSCALL_ABI_X32 16
#define SYSCALL_PTREGS 32

