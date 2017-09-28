
void dump_syscall(Capio &c, Process &p, struct user_regs_struct &regs, const char *fmt ...);
void dump_syscall_start(Capio &c, Process &p, struct user_regs_struct &regs);
void dump_syscall_argsv(Capio &c, Process &p, const char *fmt, va_list args);
void dump_syscall_end(Capio &c, Process &p, struct user_regs_struct &regs);
void dump_syscall_wo_endl(Capio &c, Process &p, struct user_regs_struct &regs, const char *fmt ...);

void dump_io(Capio &c, Process &p, struct user_regs_struct &regs, long long mem, size_t len);
void dump_iov(Capio &c, Process &p, struct user_regs_struct &regs, long long mem, long long len);

