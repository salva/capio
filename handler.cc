#include <syscall.h>
#include <bits/stdc++.h>

#include "capio.h"
#include "syscall.h"
#include "regs.h"
#include "dumper.h"
#include "handler.h"
#include "flags.h"
#include "memory.h"
#include "util.h"

using namespace std;

static void
handle_read_write(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0)) {
        dump_syscall(c, p, regs, "fd:%lld", ARG0);
        dump_io(c, p, regs, ARG1, RC);
    }
}

static void
handle_readv_writev(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0)) {
        dump_syscall(c, p, regs, "fd:%lld", ARG0);
        dump_iov(c, p, regs, ARG1, ARG2);
    }
}

static void
handle_recvfrom_sendto(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0)) {
        dump_syscall(c, p, regs,
                     "fd:%lld, flags:%s",
                     ARG0, msg_flags2string(ARG3).c_str());
        dump_io(c, p, regs, ARG1, RC);
    }
}

static void
handle_recvmsg_sendmsg(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0)) {
        struct msghdr msg;
        read_proc_struct(p.pid, ARG1, sizeof(msg), (void*)&msg);
        dump_syscall(c, p, regs,
                     "fd:%lld, name:%s, iovlen:%lld, control:%s",
                     ARG0,
                     read_proc_string_quoted(p.pid, (long long)msg.msg_name,
                                             msg.msg_namelen).c_str(),
                     msg.msg_iovlen,
                     read_proc_string_quoted(p.pid, (long long)msg.msg_control,
                                             msg.msg_controllen).c_str());
        dump_iov(c, p, regs, (long long)msg.msg_iov, msg.msg_iovlen);
    }
}

static void
handle_pread64_pwrite64(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0)) {
        dump_syscall(c, p, regs, "fd:%lld, pos:%lld", ARG0, ARG3);
        dump_io(c, p, regs, ARG1, RC);
    }
}

static void
handle_preadv_pwritev(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0)) {
        dump_syscall(c, p, regs,
                     "fd:%lld, pos:%lld (l:%lld, h:%ldd)",
                     ARG0, ARG3 + (ARG4 << 32), ARG3, ARG4);
        dump_iov(c, p, regs, ARG1, ARG2);
    }
}

static void
handle_preadv2_pwritev2(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0)) {
        dump_syscall(c, p, regs,
                     "fd:%lld, pos:%lld (l:%lld, h:%ldd), flags:%s",
                     ARG0, ARG3 + (ARG4 << 32), ARG3, ARG4,
                     rwf_flags2string(ARG5).c_str());
        dump_iov(c, p, regs, ARG1, ARG2);
    }
}

static void
handle_pipe_pipe2(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP) && !c.quiet) {
        int filedes[2];
        read_proc_struct(p.pid, (long long)ARG0, sizeof(filedes), filedes);
        if (p.dumping_fd(filedes[0]) || p.dumping_fd(filedes[1])) {
            switch(OP) {
            case SYS_pipe:
                dump_syscall_wo_endl(c, p, regs,
                                     "fds:[%d, %d]",
                                     filedes[0], filedes[1]);
                break;
            case SYS_pipe2:
                dump_syscall_wo_endl(c, p, regs,
                                     "fds:[%d, %d], flags:%s",
                                     filedes[0], filedes[1],
                                     o_flags2string(ARG1).c_str());
                break;
            }
            dual_ostream &out = c.out(p);
            out << "; paths:[";
            put_quoted(out, p.fd_path(filedes[0]));
            out << ", ";
            put_quoted(out, p.fd_path(filedes[1]));
            out << "]" << endl;
        }
    }
}

void
handle_syscall___sysctl(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP))
        dump_syscall(c, p, regs,
                     "args:%s",
                     read_proc_sysctl_args(p.pid, ARG0).c_str());
}

void
handle_syscall__accept(Capio &c, Process &p, struct user_regs_struct &regs) {
    p.close_fd(RC);
    if (c.dumping(p, OP, ARG0, RC))
        dump_syscall(c, p, regs, "fd:%lld, addr:%s",
                     ARG0,
                     read_proc_sockaddr(p.pid, ARG1, ARG2).c_str());
}

void
handle_syscall__accept4(Capio &c, Process &p, struct user_regs_struct &regs) {
    p.close_fd(RC);
    if (c.dumping(p, OP, ARG0, RC))
        dump_syscall(c, p, regs, "fd:%lld, addr:%s, flags:%s",
                     ARG0,
                     read_proc_sockaddr(p.pid, ARG1, ARG2).c_str(),
                     sock_flags2string(ARG3).c_str());
}

void
handle_syscall__access(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP)) {
        if (ARG0) {
            string abspath = p.resolve_path(read_proc_c_string(p.pid, ARG0));
            if (c.dumping_path(abspath)) {
                dump_syscall_wo_endl(c, p, regs, "path:%s, mode:0%03o",
                                     read_proc_c_string_quoted(p.pid, ARG0).c_str(),
                                     ARG1);
                dual_ostream &out = c.out(p);
                out << "; path:";
                put_quoted(out, abspath);
                out << endl;
            }
        }
        else {
            dump_syscall(c, p, regs, "path:NULL");
        }
    }
}

void
handle_syscall__acct(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP)) {
        if (!ARG0 || c.dumping_path(read_proc_c_string(p.pid, ARG0))) {
        }
    }
}

void
handle_syscall__add_key(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__adjtimex(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__afs_syscall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__alarm(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__arch_prctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__bind(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs,
                     "fd:%lld, addr:%s",
                     ARG0, read_proc_sockaddr(p.pid, ARG1, ARG2).c_str());
}

void
handle_syscall__bpf(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__brk(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__capget(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__capset(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__chdir(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__chmod(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__chown(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__chroot(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__clock_adjtime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__clock_getres(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__clock_gettime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__clock_nanosleep(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__clock_settime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__clone(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP))
        dump_syscall(c, p, regs,
                     "flags:%s, child_stack:0x%llx, ptid:%s, ctid:%s, newtls:0x%llx",
                     clone_flags2string(ARG0).c_str(),
                     ARG1,
                     read_proc_int(p.pid, ARG2).c_str(),
                     read_proc_int(p.pid, ARG3).c_str(),
                     ARG4);
}

void
handle_syscall__close(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld", ARG0);
    p.close_fd(ARG0);
}

void
handle_syscall__connect(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs,
                     "fd:%lld, addr:%s",
                     ARG0, read_proc_sockaddr(p.pid, ARG1, ARG2).c_str());
    p.close_fd(ARG0);
}

void
handle_syscall__copy_file_range(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__creat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__create_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__delete_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__dup(Capio &c, Process &p, struct user_regs_struct &regs) {
    c.dup_fd(p, ARG0, RC);
    if (c.dumping(p, OP, ARG0, RC))
        dump_syscall(c, p, regs, "fd:%lld", ARG0);
}

void
handle_syscall__dup2(Capio &c, Process &p, struct user_regs_struct &regs) {
    c.dup_fd(p, ARG0, ARG1);
    if (c.dumping(p, OP, ARG0, RC))
        dump_syscall(c, p, regs, "oldfd:%lld, newfd:%lld", ARG0, ARG1);

}

void
handle_syscall__dup3(Capio &c, Process &p, struct user_regs_struct &regs) {
    c.dup_fd(p, ARG0, ARG1);
    if (c.dumping(p, OP, ARG0, RC))
        dump_syscall(c, p, regs, "oldfd:%lld, newfd:%lld, flags:%s",
                     ARG0, ARG1, o_flags2string(ARG2).c_str());
}

void
handle_syscall__epoll_create(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__epoll_create1(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__epoll_ctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__epoll_ctl_old(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__epoll_pwait(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__epoll_wait(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__epoll_wait_old(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__eventfd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__eventfd2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__execve(Capio &c, Process &p, struct user_regs_struct &regs) {
    bool was_dumping = c.dumping(p, OP);
    p.reset_process_name();
    if (!c.quiet && (was_dumping || c.dumping(p, OP))) {
        dump_syscall_wo_endl(c, p, regs, "%s", p.enter_args.c_str());
        dual_ostream &out = c.out(p);
        out << "; path:";
        put_quoted(out, p.process_name);
        out << endl;
    }
}

void
handle_syscall__execveat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__exit(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__exit_group(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__faccessat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fadvise64(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs,
                     "fd:%lld, offset:%lld, len:%lld, advice:%s",
                     ARG0, ARG1, ARG2,
                     posix_fadv_flags2string(ARG3).c_str());
}

void
handle_syscall__fallocate(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fanotify_init(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fanotify_mark(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fchdir(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld", ARG0);
}

void
handle_syscall__fchmod(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, mode:0%llo", ARG0, ARG1);
}

void
handle_syscall__fchmodat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fchown(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, user:%lld, group:%lld", ARG0, ARG1, ARG2);
}

void
handle_syscall__fchownat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fcntl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fdatasync(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld", ARG0);
}

void
handle_syscall__fgetxattr(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, ...", ARG0);
}

void
handle_syscall__finit_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__flistxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__flock(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, operation:%s", ARG0,
                     lock_flags2string(ARG1).c_str());
}

void
handle_syscall__fork(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fremovexattr(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, ...", ARG0);

}

void
handle_syscall__fsetxattr(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, ...", ARG0);
}

void
handle_syscall__fstat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__fstatfs(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, buf:...", ARG0);
}

void
handle_syscall__fsync(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld", ARG0);
}

void
handle_syscall__ftruncate(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, length:%lld", ARG0, ARG1);
}

void
handle_syscall__futex(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__futimesat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__get_kernel_syms(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__get_mempolicy(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__get_robust_list(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__get_thread_area(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getcpu(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getcwd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getdents(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, dirents:[...]", ARG0);
}

void
handle_syscall__getdents64(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, dirents:[...]", ARG0);
}

void
handle_syscall__getegid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__geteuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getgroups(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getitimer(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getpeername(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getpgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getpgrp(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getpid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getpmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getppid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getpriority(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getrandom(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getresgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getresuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getrlimit(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getrusage(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getsid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getsockname(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getsockopt(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__gettid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__gettimeofday(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__getxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__init_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__inotify_add_watch(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, path:%s, mask:%s",
                     ARG0,
                     read_proc_c_string_quoted(p.pid, ARG1).c_str(),
                     in_flags2string(ARG2).c_str());
}

void
handle_syscall__inotify_init(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP,RC))
        dump_syscall(c, p, regs, "");
}

void
handle_syscall__inotify_init1(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP,RC))
        dump_syscall(c, p, regs,
                     "flags:%s",
                     in_init1_flags2string(ARG0).c_str());
}

void
handle_syscall__inotify_rm_watch(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, wd:%lld", ARG0, ARG1);

}

void
handle_syscall__io_cancel(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__io_destroy(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__io_getevents(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__io_setup(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__io_submit(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__ioctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__ioperm(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__iopl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__ioprio_get(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__ioprio_set(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__kcmp(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__kexec_file_load(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__kexec_load(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__keyctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__kill(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__lchown(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__lgetxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__link(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__linkat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__listen(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs,
                     "fd:%lld, backlog:%lld",
                     ARG0, ARG1);
}

void
handle_syscall__listxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__llistxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__lookup_dcookie(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__lremovexattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__lseek(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__lsetxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__lstat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__madvise(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mbind(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__membarrier(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__memfd_create(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__migrate_pages(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mincore(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mkdir(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mkdirat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mknod(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mknodat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mlock(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mlock2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mlockall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mmap(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (ARG4 >= 0) {
        if (c.dumping(p, OP, ARG4))
            dump_syscall(c, p, regs,
                         "addr:0x%llx, length:%lld, prot:%s, flags:%s, fd:%lld, offset:%lld",
                         ARG0, ARG1,
                         prot_flags2string(ARG2).c_str(),
                         map_flags2string(ARG3).c_str(), ARG4, ARG5);
    }
}

void
handle_syscall__modify_ldt(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mount(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__move_pages(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mprotect(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mq_getsetattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mq_notify(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mq_open(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mq_timedreceive(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mq_timedsend(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mq_unlink(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__mremap(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__msgctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__msgget(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__msgrcv(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__msgsnd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__msync(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__munlock(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__munlockall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__munmap(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__name_to_handle_at(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__nanosleep(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__newfstatat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__nfsservctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__open(Capio &c, Process &p, struct user_regs_struct &regs) {
    p.close_fd(RC);
    if (c.dumping(p, OP,RC)) {
        if (!c.quiet) {
            dump_syscall_wo_endl(c, p, regs,
                                 "filename:%s, flags:%s, mode:0%03llo",
                                 read_proc_c_string_quoted(p.pid, ARG0).c_str(),
                                 o_flags2string(ARG1).c_str(),
                                 ARG2);
            dual_ostream &out = c.out(p);
            out << "; path:";
            put_quoted(out, p.fd_path(RC));
            out << endl;
        }
    }
}

void
handle_syscall__open_by_handle_at(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__openat(Capio &c, Process &p, struct user_regs_struct &regs) {
    p.close_fd(RC);
    if (c.dumping(p, OP, ARG0, RC))
        dump_syscall(c, p, regs,
                     "dfd:%lld, path:%s, flags:%s, mode:0%03llo",
                     ARG0,
                     read_proc_c_string_quoted(p.pid, ARG1).c_str(),
                     o_flags2string(ARG2).c_str(),
                     ARG3);
}

void
handle_syscall__pause(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__perf_event_open(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__personality(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__pipe(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_pipe_pipe2(c, p, regs);
}

void
handle_syscall__pipe2(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_pipe_pipe2(c, p, regs);
}

void
handle_syscall__pivot_root(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__pkey_alloc(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__pkey_free(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__pkey_mprotect(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__poll(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__ppoll(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__prctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__pread64(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_pread64_pwrite64(c, p, regs);
}

void
handle_syscall__preadv(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_preadv_pwritev(c, p, regs);
}

void
handle_syscall__preadv2(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_preadv2_pwritev2(c, p, regs);
}

void
handle_syscall__prlimit64(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__process_vm_readv(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_readv_writev(c, p, regs);
}

void
handle_syscall__process_vm_writev(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__pselect6(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__ptrace(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__putpmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__pwrite64(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_pread64_pwrite64(c, p, regs);
}

void
handle_syscall__pwritev(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_preadv_pwritev(c, p, regs);
}

void
handle_syscall__pwritev2(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_preadv2_pwritev2(c, p, regs);
}

void
handle_syscall__query_module(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__quotactl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__read(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_read_write(c, p, regs);
}

void
handle_syscall__readahead(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs, "fd:%lld, offset:%lld, count:%lld", ARG0, ARG1, ARG2);
}

void
handle_syscall__readlink(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__readlinkat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__readv(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__reboot(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__recvfrom(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_recvfrom_sendto(c, p, regs);
}

void
handle_syscall__recvmmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__recvmsg(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_recvmsg_sendmsg(c, p, regs);
}

void
handle_syscall__remap_file_pages(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__removexattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rename(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__renameat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__renameat2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__request_key(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__restart_syscall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rmdir(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rt_sigaction(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rt_sigpending(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rt_sigprocmask(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rt_sigqueueinfo(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rt_sigreturn(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rt_sigsuspend(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rt_sigtimedwait(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__rt_tgsigqueueinfo(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_get_priority_max(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_get_priority_min(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_getaffinity(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_getattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_getparam(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_getscheduler(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_rr_get_interval(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_setaffinity(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_setattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_setparam(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_setscheduler(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sched_yield(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__seccomp(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__security(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__select(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__semctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__semget(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__semop(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__semtimedop(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sendfile(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs,
                     "out_fd:%lld, in_fd:%lld, offset:%lld",
                     ARG0, ARG1, ARG2);
}

void
handle_syscall__sendmmsg(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sendmsg(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_recvmsg_sendmsg(c, p, regs);
}

void
handle_syscall__sendto(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_recvfrom_sendto(c, p, regs);
}

void
handle_syscall__set_mempolicy(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__set_robust_list(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__set_thread_area(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__set_tid_address(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setdomainname(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setfsgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setfsuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setgroups(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sethostname(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setitimer(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setns(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setpgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setpriority(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setregid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setresgid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setresuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setreuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setrlimit(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setsid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setsockopt(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__settimeofday(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setuid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__setxattr(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__shmat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__shmctl(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__shmdt(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__shmget(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__shutdown(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0))
        dump_syscall(c, p, regs,
                     "fd:%lld, how:%s",
                     ARG0,
                     shut_flags2string(ARG1).c_str());
}

void
handle_syscall__sigaltstack(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__signalfd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__signalfd4(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__socket(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, RC)) {
        dump_syscall_wo_endl(c, p, regs,
                             "domain:%s, type:%s, protocol:%lld",
                             af_flags2string(ARG0).c_str(),
                             sock_flags2string(ARG1).c_str(),
                             ARG2);
        dual_ostream &out = c.out(p);
        out << "; path:";
        put_quoted(out, p.fd_path(RC));
        out << endl;
    }
}

void
handle_syscall__socketpair(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP) && !c.quiet) {
        int usockvec[2];
        read_proc_struct(p.pid, (long long)ARG3, sizeof(usockvec), usockvec);
        if (p.dumping_fd(usockvec[0]) || p.dumping_fd(usockvec[1])) {
            dump_syscall_wo_endl(c, p, regs,
                                 "domain:%s, type:%s, protocol:%lld fds:[%d, %d]",
                                 af_flags2string(ARG0).c_str(),
                                 sock_flags2string(ARG1).c_str(),
                                 ARG2,
                                 usockvec[0], usockvec[1]);
            dual_ostream &out = c.out(p);
            out << "; paths:[";
            put_quoted(out, p.fd_path(usockvec[0]));
            out << ", ";
            put_quoted(out, p.fd_path(usockvec[1]));
            out << "]" << endl;
        }
    }
}

void
handle_syscall__splice(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0, ARG2))
        dump_syscall(c, p, regs,
                     "fd_in:%lld, off_in:%s, fd_out:%lld, off_out:%s, len:%lld, flags:%s",
                     ARG0,
                     read_proc_off_t(p.pid, ARG1).c_str(),
                     ARG2,
                     read_proc_off_t(p.pid, ARG3).c_str(),
                     ARG4,
                     splice_flags2string(ARG5).c_str());
}

void
handle_syscall__stat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__statfs(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__statx(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__swapoff(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__swapon(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__symlink(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__symlinkat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sync(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sync_file_range(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__syncfs(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sysfs(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__sysinfo(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__syslog(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__tee(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (c.dumping(p, OP, ARG0, ARG1))
        dump_syscall(c, p, regs, "fdin:%lld, fdout:%lld, len:%lld, flags:%s",
                     ARG0, ARG1, ARG2,
                     splice_flags2string(ARG3).c_str());
}

void
handle_syscall__tgkill(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__time(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__timer_create(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__timer_delete(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__timer_getoverrun(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__timer_gettime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__timer_settime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__timerfd_create(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__timerfd_gettime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__timerfd_settime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__times(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__tkill(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__truncate(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__tuxcall(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__umask(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__umount2(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__uname(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__unlink(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__unlinkat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__unshare(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__uselib(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__userfaultfd(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__ustat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__utime(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__utimensat(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__utimes(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__vfork(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__vhangup(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__vmsplice(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__vserver(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__wait4(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__waitid(Capio &c, Process &p, struct user_regs_struct &regs) {

}

void
handle_syscall__write(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_read_write(c, p, regs);
}

void
handle_syscall__writev(Capio &c, Process &p, struct user_regs_struct &regs) {
    handle_readv_writev(c, p, regs);
}

void
handle_syscall_unexpected(Capio &c, Process &p, struct user_regs_struct &regs) {

}

