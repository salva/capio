#include "capio.h"
#include "syscall.h"
#include "regs.h"
#include "memory.h"
#include "flags.h"
#include "util.h"

using namespace std;

void
dump_syscall_start(Capio &c, Process &p, struct user_regs_struct &regs) {
    dual_ostream &out = c.out(p);
    out << "# ";
    if (c.dump_children)
        out << p.pid << " ";
    out << syscalls[OP].name;
}

void
dump_syscall_argsv(Capio &c, Process &p, const char *fmt, va_list args) {
    dual_ostream &out = c.out(p);
    size_t available = 4096;
    while (1) {
        va_list args_cp;
        va_copy(args_cp, args);
        char *buff = (char *)get_buffer(available);
        size_t required = vsnprintf(buff, available, fmt, args_cp);
        va_end(args_cp);
        if (required < available) {
            out << "(" << buff << ")";
            break;
        }
        available = required + 10;
    }
}

void
dump_syscall_end(Capio &c, Process &p, struct user_regs_struct &regs) {
    dual_ostream &out = c.out(p);
    if (RC < 0)
        out << " = -1, errno:" << e_flags2string(-RC);
    else
        out << " = " << RC;
}

void
dump_syscall_wo_endl(Capio &c, Process &p, struct user_regs_struct &regs, const char *fmt ...) {
    dump_syscall_start(c, p, regs);
    va_list args;
    va_start(args, fmt);
    dump_syscall_argsv(c, p, fmt, args);
    va_end(args);
    dump_syscall_end(c, p, regs);
}

void
dump_syscall(Capio &c, Process &p, struct user_regs_struct &regs, const char *fmt ...) {
    if (!c.quiet) {
        dump_syscall_start(c, p, regs);
        va_list args;
        va_start(args, fmt);
        dump_syscall_argsv(c, p, fmt, args);
        va_end(args);
        dump_syscall_end(c, p, regs);
        c.out(p) << endl;
    }
}

#define LINELEN 32
static void dump_hex(ostream &out, bool writting, const unsigned char *data, size_t len) {
    int dir = (writting ? '>' : '<');
    int lines = (len + LINELEN - 1) / LINELEN;
    for (int i = 0; i < lines; i++) {
        out.put(dir);
        for (int j = 0; j < LINELEN; j++) {
            int off = i * LINELEN + j;
            if (off < len) {
                char hex[10];
                sprintf(hex, " %02x", data[off]);
                out << hex;
            }
            else
                out << " __";
        }
        out << " "; out.put(dir); out << " ";
        for (int j = 0; j < LINELEN; j++) {
            int off = i * LINELEN + j;
            if (off >= len) break;
            out.put(isprint(data[off]) ? data[off] : '.');
        }
        out << endl << flush;
    }
}

static void
dump_quoted(ostream &out, bool writting, const unsigned char *data, size_t len, bool breaks) {
    if (len) {
        put_quoted(out, data, len, breaks, (writting ? "> " : "< "));
        out << endl << flush;
    }
}

static void
dump_raw(ostream &out, const unsigned char *data, size_t len) {
    out.write(reinterpret_cast<const char *>(data), len);
    out << flush;
}

void
dump_mem(Capio &c, Process &p, struct user_regs_struct &regs, long long mem, size_t len) {
    dual_ostream &out = c.out(p);
    bool writting = syscalls[OP].writes();
    const unsigned char *data = read_proc_mem(p.pid, mem, len);
    switch (c.format) {
    case 'x':
        dump_hex(out, writting, data, len);
        break;
    case 'q':
        dump_quoted(out, writting, data, len, false);
        break;
    case 'n':
        dump_quoted(out, writting, data, len, true);
        break;
    case 'r':
        dump_raw(out, data, len);
        break;
    case '0':
        break;
    default:
        debug(1, "Format %c not implemented yet", c.format);
        break;
    }
}

void
dump_iov(Capio &c, Process &p, struct user_regs_struct &regs, long long mem, long long len) {
    size_t remaining = RC;
    auto vec = (struct iovec *)mem;
    for (size_t i = 0; remaining && i < len; i++) {
        struct iovec iov;
        read_proc_struct(p.pid, (long long)(vec + i), sizeof(iov), &iov);
        size_t chunk = ((remaining > iov.iov_len) ? iov.iov_len : remaining);
        dump_mem(c, p, regs, (long long)iov.iov_base, chunk);
#ifdef WITH_PERL
        if (perl_flag)
            dump_perl(out, p, fd, syscall_name, rc, writting, (long long)iov.iov_base, chunk);
#endif
        remaining -= chunk;
    }
}

static void
dump_syscall_read_write(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (p.dumping_fd(ARG0)) {
        dump_syscall(c, p, regs, "fd:%lld", ARG0);
    }
}


void
dump_syscall___sysctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__accept(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__accept4(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__access(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__acct(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__add_key(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__adjtimex(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__afs_syscall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__alarm(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__arch_prctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__bind(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__bpf(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__brk(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__capget(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__capset(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__chdir(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__chmod(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__chown(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__chroot(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__clock_adjtime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__clock_getres(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__clock_gettime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__clock_nanosleep(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__clock_settime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__clone(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__close(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__connect(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__copy_file_range(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__creat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__create_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__delete_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__dup(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__dup2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__dup3(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__epoll_create(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__epoll_create1(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__epoll_ctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__epoll_ctl_old(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__epoll_pwait(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__epoll_wait(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__epoll_wait_old(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__eventfd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__eventfd2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__execve(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__execveat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__exit(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__exit_group(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__faccessat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fadvise64(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fallocate(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fanotify_init(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fanotify_mark(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fchdir(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fchmod(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fchmodat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fchown(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fchownat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fcntl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fdatasync(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fgetxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__finit_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__flistxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__flock(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fork(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fremovexattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fsetxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fstat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fstatfs(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__fsync(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__ftruncate(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__futex(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__futimesat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__get_kernel_syms(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__get_mempolicy(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__get_robust_list(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__get_thread_area(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getcpu(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getcwd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getdents(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getdents64(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getegid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__geteuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getgroups(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getitimer(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getpeername(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getpgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getpgrp(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getpid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getpmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getppid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getpriority(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getrandom(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getresgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getresuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getrlimit(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getrusage(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getsid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getsockname(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getsockopt(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__gettid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__gettimeofday(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__getxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__init_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__inotify_add_watch(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__inotify_init(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__inotify_init1(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__inotify_rm_watch(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__io_cancel(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__io_destroy(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__io_getevents(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__io_setup(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__io_submit(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__ioctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__ioperm(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__iopl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__ioprio_get(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__ioprio_set(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__kcmp(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__kexec_file_load(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__kexec_load(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__keyctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__kill(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__lchown(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__lgetxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__link(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__linkat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__listen(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__listxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__llistxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__lookup_dcookie(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__lremovexattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__lseek(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__lsetxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__lstat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__madvise(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mbind(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__membarrier(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__memfd_create(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__migrate_pages(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mincore(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mkdir(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mkdirat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mknod(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mknodat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mlock(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mlock2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mlockall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mmap(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__modify_ldt(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mount(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__move_pages(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mprotect(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mq_getsetattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mq_notify(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mq_open(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mq_timedreceive(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mq_timedsend(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mq_unlink(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__mremap(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__msgctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__msgget(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__msgrcv(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__msgsnd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__msync(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__munlock(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__munlockall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__munmap(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__name_to_handle_at(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__nanosleep(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__newfstatat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__nfsservctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__open(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__open_by_handle_at(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__openat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pause(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__perf_event_open(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__personality(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pipe(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pipe2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pivot_root(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pkey_alloc(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pkey_free(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pkey_mprotect(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__poll(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__ppoll(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__prctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pread64(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__preadv(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__preadv2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__prlimit64(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__process_vm_readv(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__process_vm_writev(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pselect6(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__ptrace(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__putpmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pwrite64(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pwritev(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__pwritev2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__query_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__quotactl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__read(Capio &c, Process &p, struct user_regs_struct &regs) {
    dump_syscall_read_write(c, p, regs);
}

void
dump_syscall__readahead(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__readlink(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__readlinkat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__readv(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__reboot(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__recvfrom(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__recvmmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__recvmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__remap_file_pages(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__removexattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rename(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__renameat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__renameat2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__request_key(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__restart_syscall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rmdir(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rt_sigaction(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rt_sigpending(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rt_sigprocmask(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rt_sigqueueinfo(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rt_sigreturn(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rt_sigsuspend(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rt_sigtimedwait(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__rt_tgsigqueueinfo(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_get_priority_max(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_get_priority_min(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_getaffinity(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_getattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_getparam(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_getscheduler(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_rr_get_interval(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_setaffinity(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_setattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_setparam(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_setscheduler(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sched_yield(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__seccomp(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__security(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__select(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__semctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__semget(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__semop(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__semtimedop(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sendfile(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sendmmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sendmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sendto(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__set_mempolicy(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__set_robust_list(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__set_thread_area(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__set_tid_address(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setdomainname(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setfsgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setfsuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setgroups(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sethostname(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setitimer(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setns(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setpgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setpriority(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setregid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setresgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setresuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setreuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setrlimit(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setsid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setsockopt(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__settimeofday(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__setxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__shmat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__shmctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__shmdt(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__shmget(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__shutdown(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sigaltstack(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__signalfd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__signalfd4(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__socket(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__socketpair(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__splice(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__stat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__statfs(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__statx(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__swapoff(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__swapon(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__symlink(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__symlinkat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sync(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sync_file_range(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__syncfs(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sysfs(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__sysinfo(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__syslog(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__tee(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__tgkill(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__time(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__timer_create(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__timer_delete(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__timer_getoverrun(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__timer_gettime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__timer_settime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__timerfd_create(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__timerfd_gettime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__timerfd_settime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__times(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__tkill(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__truncate(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__tuxcall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__umask(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__umount2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__uname(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__unlink(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__unlinkat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__unshare(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__uselib(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__userfaultfd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__ustat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__utime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__utimensat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__utimes(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__vfork(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__vhangup(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__vmsplice(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__vserver(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__wait4(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__waitid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall__write(Capio &c, Process &p, struct user_regs_struct &regs) {
    dump_syscall_read_write(c, p, regs);
}

void
dump_syscall__writev(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
dump_syscall_unexpected(Capio &c, Process &p, struct user_regs_struct &regs) {

}

