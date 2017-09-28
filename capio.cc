
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <syscall.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <bits/stdc++.h>

#include <linux/netlink.h>
#include <linux/un.h>
//#include <linux/in.h>

using namespace std;

#include "capio.h"
#include "syscall.h"
#include "flags.h"
#include "sockaddr.h"
#include "util.h"
#include "regs.h"
#include "dumper.h"
#include "memory.h"
#include "group.h"
#include "handler.h"

static int debug_level = 0;
static unordered_map<int, bool> dumping_fds;
static forward_list<string> exe_patterns;
static forward_list<string> fn_patterns;

#ifdef WITH_PERL
static string perl_code;
static char perl_flag = '\0';
#include "perl.h"
#endif

void
debug(int level, const char *fmt...) {
    if (level <= debug_level) {
        va_list ap;
        fputs("debug> ", stderr);
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputs("\n", stderr);
        fflush(stderr);
    }
}

static bool
match_fn_patterns(const forward_list<string> &patterns, const string &target) {
    if (patterns.empty()) return true;
    for (auto it = patterns.begin(); it != patterns.end(); it++) {
        debug(4, "matching %s against %s", target.c_str(), it->c_str());
        if (fnmatch(it->c_str(), target.c_str(), 0) == 0)
            return true;
        debug(4, "continuing...");
    }
    return false;
}

static string
proc_readlink(pid_t pid, const string &link) {
    char buffer[PATH_MAX+2];
    string path = "/proc/" + to_string(pid) + "/" + link;
    size_t len = readlink(path.c_str(), buffer, PATH_MAX);
    if (len < 0) return "???";
    buffer[len] = '\0';
    return buffer;
}

static string
get_process_name(pid_t pid) {
    return proc_readlink(pid, "exe");
}

static string
get_process_filename(pid_t pid, int fd) {
    return proc_readlink(pid, "fd/" + to_string(fd));
}

static unordered_map<pid_t, Process*> processes;

Process::Process(pid_t pid)
    : pid(pid), dumping(true),
      sigcall_exiting(false), initialized(false), out(NULL) {
    reset_process_name();
    debug(4, "New process structure with pid %d", pid);
}

Process::~Process() {
    if (out) delete out;
}

void
Process::reset_process_name() {
    process_name = get_process_name(pid);
    dumping = match_fn_patterns(exe_patterns, process_name);
    debug(2, "process name for pid %d is %s, dumping is %d\n", pid, process_name.c_str(), (int)dumping);
}

const string&
Process::fd_path(int fd) {
    return fdgroup(fd)->path;
}

FDGroup::FDGroup(int fd, string path_) : path(path_) {
    fds.push_front(fd);
    debug(4, "checking dumping for fd %d, empty: %d, dumping_fd[%d] = %d",
          fd, dumping_fds.empty(), fd, dumping_fds.count(fd));
    dumping = ((dumping_fds.empty() || dumping_fds.count(fd)) &&
               match_fn_patterns(fn_patterns, path_));
}

FDGroup *
Process::fdgroup(int fd) {
    FDGroup *grp = fdgroups[fd];
    if (!grp)
        fdgroups[fd] = grp = new FDGroup(fd, get_process_filename(pid, fd));
    return grp;
}

void
Process::close_fd(int fd) {
    if (fdgroups.count(fd)) {
        if (FDGroup *grp = fdgroups[fd]) {
            grp->rm_fd(fd);
            if (grp->empty())
                delete grp;
        }
        fdgroups.erase(fd);
    }
}

void
Process::dup_fd(int oldfd, int newfd) {
    if (oldfd != newfd) {
        close_fd(newfd);
        FDGroup *grp = fdgroup(oldfd);
        grp->add_fd(newfd);
        fdgroups[newfd] = grp;
    }
}

bool
Process::dumping_fd(int fd) {
    return (dumping && fdgroup(fd)->dumping);
}

bool
FDGroup::empty() {
    return fds.empty();
}

void
FDGroup::add_fd(int fd) {
    fds.push_front(fd);
    dumping |= dumping_fds.count(fd);
}

void
FDGroup::rm_fd(int fd) {
    fds.remove(fd);
    if (dumping_fds.count(fd)) {
        dumping = false;
        for (auto it = fds.begin(); it != fds.end(); it++) {
            if (dumping_fds.count(*it)) {
                dumping = true;
                break;
            }
        }
    }
    else
        dumping = true;
}

dual_ostream &Capio::out(Process &p) {
    if (p.out) return *(p.out);
    if (multifile && p.dumping) {
        p.out = new dual_ostream(*out_fn + "." + to_string(p.pid));
        return *(p.out);
    }
    return *default_out;
}

void
fatal(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[], char *env[]) {
#ifdef WITH_PERL
    init_perl(argc, argv, env);
#endif
    int opt;
    int fd;
    pid_t pid;
    Capio capio;

    while ((opt = getopt(argc, argv, "o:m:M:p:n:N:l:e:E:fdqFO")) != -1) {
        switch (opt) {
        case 'p':
            pid = atol(optarg);
            if (ptrace (PTRACE_ATTACH, pid, NULL, NULL) < 0)
                fatal("Unable to trace process");
            processes[pid] = new Process(pid);
            break;
        case 'n':
            exe_patterns.push_front(optarg);
            break;
        case 'N':
            fn_patterns.push_front(optarg);
            break;
        case 'f':
            capio.dump_children = true;
            break;
        case 'F':
            capio.dont_follow = true;
            break;
        case 'd':
            debug_level++;
            break;
        case 'l':
            fd = atol(optarg);
            dumping_fds[fd] = true;
            break;
        case 'm':
            if (strchr("xqrn0", optarg[0]) && optarg[1] == '\0') {
                capio.format = optarg[0];
            }
            else
                fatal("Bad format specifier");
            break;
        case 'o':
            capio.out_fn = new string(optarg);
            break;
        case 'O':
            capio.multifile = true;
            break;
        case 'q':
            capio.quiet = true;
            break;

        case 'e':
        case 'E':
        case 'M':
#ifdef WITH_PERL
            if (perl_flag)
                fatal("flags -e, -E and -M are exclusive");
            perl_flag = opt;
            perl_code = optarg;
            if (!capio.format)
                capio.format = '0';
#else
            fatal("This version of capio has not been compiled with perl support");
#endif
            break;
        default:
            fprintf(stderr, "Usage: %s -p PID [-p PID1 [...]]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    capio.default_out = ((capio.out_fn && !capio.multifile)
                         ? new dual_ostream(*capio.out_fn)
                         : new dual_ostream(dup(1)));


#ifdef WITH_PERL
    if (perl_flag)
        parse_perl(*default_out, perl_code);
#endif
    if (!capio.format)
        capio.format = 'x';

    if (argc > optind) {
        pid_t pid = fork();
        if (pid == 0) {
            int ac = argc - optind;
            char **av = new char* [ac + 1];
            for (int i = 0; i < ac; i++)
                av[i] = argv[optind + i];
            av[ac] = 0;

            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            execvp(av[0], av);
            _exit(0);
        }
        if (pid < 0)
            fatal("Unable to create child process");
        processes[pid] = new Process(pid);
    }

    while (!processes.empty()) {
        int wstatus;
        pid_t pid = wait(&wstatus);
        if (pid > 0) {
            Process *pp = processes[pid];
            if (!pp)
                pp = processes[pid] = new Process(pid);
            Process &p = *pp;
            if (!p.initialized) {
                int options = PTRACE_O_TRACESYSGOOD;
                if (capio.dump_children)
                    options |= PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
                if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) < 0)
                    debug(1, "Unable to set ptrace options to %d for pid %d", options, pid);
                p.initialized = true;
            }

            if (WIFSTOPPED(wstatus)) {
                int sig = WSTOPSIG(wstatus);
                debug(3, "Process %d stopped by signal %d", pid, sig);
                if (sig == (SIGTRAP|0x80)) { /* We got a syscall! */
                    if (p.sigcall_exiting) {
                        p.sigcall_exiting = false;
                        struct user_regs_struct regs;
                        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

                        debug(4, "EXIT pid: %d, orig_rax: %lld, rax: %lld, rdi: %lld, rsi: %lld, rdx: %lld, r10: %lld, r9: %lld, r8: %lld",
                              pid, OP, RC, ARG0, ARG1, ARG2, ARG3, ARG4, ARG5);

                        if (RC >= 0 || RC == -EINPROGRESS) {
                            bool writting = false;
                            bool dumping = p.dumping;
                            switch(OP) {
                            case SYS_write:
                                writting = true;
                            case SYS_read:
                                if (p.dumping_fd(ARG0)) {
                                    const char *syscall_name = (writting ? "write" : "read");
                                    dump_syscall(capio, p, regs, "fd:%lld", ARG0);
                                    dump_mem(capio, p, regs, ARG1, RC);
#ifdef WITH_PERL
                                    if (perl_flag)
                                        dump_perl(out, p, ARG0, syscall_name, RC, writting, ARG1, RC);
#endif
                                }
                                break;
                            case SYS_sendto:
                                writting = true;
                            case SYS_recvfrom:
                                if (p.dumping_fd(ARG0)) {
                                    const char *syscall_name = (writting ? "sendto" : "recvfrom");
                                    dump_syscall(capio, p, regs, "fd:%lld, flags:%s",
                                                 ARG0, msg_flags2string(ARG3).c_str());
                                    dump_mem(capio, p, regs, ARG1, RC);
#ifdef WITH_PERL
                                    if (perl_flag)
                                        dump_perl(out, p, ARG0, syscall_name, RC, writting, ARG1, RC);
#endif
                                }
                                break;
                            case SYS_open:
                                p.close_fd(RC);
                                if (p.dumping_fd(RC)) {
                                    if (!capio.quiet) {
                                        dump_syscall_wo_endl(capio, p, regs, "filename:%s, flags:%s, mode:0%03llo",
                                                             read_proc_c_string_quoted(pid, ARG0).c_str(),
                                                             o_flags2string(ARG1).c_str(),
                                                             ARG2);
                                        dual_ostream &out = capio.out(p);
                                        out << "; path:";
                                        put_quoted(out, p.fd_path(RC));
                                        out << endl;
                                    }
                                }
                                break;
                            case SYS_bind:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, addr:%s",
                                                 ARG0, read_proc_sockaddr(pid, ARG1, ARG2).c_str());
                                break;
                            case SYS_listen:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, backlog:%lld", ARG0, ARG1);
                                break;
                            case SYS_sendmsg:
                                writting = true;
                            case SYS_recvmsg:
                                if (p.dumping_fd(ARG0)) {
                                    const char *syscall_name = (writting ? "sendmsg" : "recvmsg");
                                    struct msghdr msg;
                                    read_proc_struct(pid, ARG1, sizeof(msg), (void*)&msg);
                                    dump_syscall(capio, p, regs,
                                                 "fd:%lld, name:%s, iovlen:%lld, control:%s",
                                                 ARG0,
                                                 read_proc_string_quoted(pid, (long long)msg.msg_name,
                                                                         msg.msg_namelen).c_str(),
                                                 msg.msg_iovlen,
                                                 read_proc_string_quoted(pid, (long long)msg.msg_control,
                                                                         msg.msg_controllen).c_str());
                                    dump_iov(capio, p, regs, (long long)msg.msg_iov, msg.msg_iovlen);
                                }
                                break;
                            case SYS_shutdown:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, how:%s", ARG0,
                                                 shut_flags2string(ARG1).c_str());
                                break;
                            case SYS_pwrite64:
                                writting = true;
                            case SYS_pread64:
                                if (p.dumping_fd(ARG0)) {
                                    const char *syscall_name = (writting ? "pwrite" : "pread");
                                    dump_syscall(capio, p, regs, "fd:%lld, pos:%lld", ARG0, ARG3);
                                    dump_mem(capio, p, regs, ARG1, RC);
#ifdef WITH_PERL
                                    if (perl_flag)
                                        dump_perl(out, p, ARG0, syscall_name, RC, writting, ARG1, RC);
#endif
                                }
                                break;
                            case SYS_pwritev:
                                writting = 1;
                            case SYS_preadv:
                                if (p.dumping_fd(ARG0)) {
                                    const char *syscall_name = (writting ? "pwritev" : "preadv");
                                    dump_syscall(capio, p, regs,
                                                 "fd:%lld, pos:%lld (l:%lld, h:%ldd)",
                                                 ARG0, ARG3 + (ARG4 << 32), ARG3, ARG4);
                                    dump_iov(capio, p, regs, ARG1, ARG2);
                                }
                                break;
                            case SYS_pwritev2:
                                writting = true;
                            case SYS_preadv2:
                                if (p.dumping_fd(ARG0)) {
                                    const char *syscall_name = (writting ? "pwritev" : "preadv");
                                    dump_syscall(capio, p, regs,
                                                 "fd:%lld, pos:%lld (l:%lld, h:%ldd), flags:%s",
                                                 ARG0, ARG3 + (ARG4 << 32), ARG3, ARG4,
                                                 rwf_flags2string(ARG5).c_str());
                                    dump_iov(capio, p, regs, ARG1, ARG2);
                                }
                                break;
                            case SYS_writev:
                                writting = 1;
                            case SYS_readv:
                                if (p.dumping_fd(ARG0)) {
                                    const char *syscall_name = (writting ? "writev" : "readv");
                                    dump_syscall(capio, p, regs, "fd:%lld", ARG0);
                                    dump_iov(capio, p, regs, ARG1, ARG2);
                                }
                                break;
                            case SYS_pipe:
                                if (p.dumping && !capio.quiet) {
                                    int filedes[2];
                                    read_proc_struct(pid, (long long)ARG0, sizeof(filedes), filedes);
                                    if (p.dumping_fd(filedes[0]) || p.dumping_fd(filedes[1])) {
                                        dump_syscall_wo_endl(capio, p, regs,
                                                             "fds:[%d, %d], flags:%s",
                                                             filedes[0], filedes[1],
                                                             o_flags2string(ARG1).c_str());
                                        dual_ostream &out = capio.out(p);
                                        out << "; paths:[";
                                        put_quoted(out, p.fd_path(filedes[0]));
                                        out << ", ";
                                        put_quoted(out, p.fd_path(filedes[1]));
                                        out << "]" << endl;
                                    }
                                }
                                break;
                            case SYS_socketpair:
                                if (p.dumping && !capio.quiet) {
                                    int usockvec[2];
                                    read_proc_struct(pid, (long long)ARG3, sizeof(usockvec), usockvec);
                                    if (p.dumping_fd(usockvec[0]) || p.dumping_fd(usockvec[1])) {
                                        dump_syscall_wo_endl(capio, p, regs,
                                                             "domain:%s, type:%s, protocol:%lld fds:[%d, %d]",
                                                             af_flags2string(ARG0).c_str(),
                                                             sock_flags2string(ARG1).c_str(),
                                                             ARG2,
                                                             usockvec[0], usockvec[1]);
                                        dual_ostream &out = capio.out(p);
                                        out << "; paths:[";
                                        put_quoted(out, p.fd_path(usockvec[0]));
                                        out << ", ";
                                        put_quoted(out, p.fd_path(usockvec[1]));
                                        out << "]" << endl;
                                    }
                                }
                                break;
                            case SYS_sendfile:
                                if (p.dumping_fd(ARG0) || p.dumping_fd(ARG1))
                                    dump_syscall(capio, p, regs,
                                                 "out_fd:%lld, in_fd:%lld, offset:%lld -- data not available)",
                                                 ARG0, ARG1, ARG2);
                                break;
                            case SYS_socket:
                                if (p.dumping_fd(RC)) {
                                    dump_syscall_wo_endl(capio, p, regs,
                                                         "domain:%s, type:%s, protocol:%lld",
                                                         af_flags2string(ARG0).c_str(),
                                                         sock_flags2string(ARG1).c_str(),
                                                         ARG2);
                                    dual_ostream &out = capio.out(p);
                                    out << "; path:";
                                    put_quoted(out, p.fd_path(RC));
                                    out << endl;
                                }
                                break;
                            case SYS_connect:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs,
                                                 "fd:%lld, addr:%s",
                                                 ARG0, read_proc_sockaddr(pid, ARG1, ARG2).c_str());
                                break;
                            case SYS_accept:
                                p.close_fd(RC);
                                if (p.dumping_fd(ARG0) || p.dumping_fd(RC))
                                    dump_syscall(capio, p, regs, "fd:%lld, addr:%s",
                                                 ARG0,
                                                 read_proc_sockaddr(pid, ARG1, ARG2).c_str());
                                break;
                            case SYS_accept4:
                                p.close_fd(RC);
                                if (p.dumping_fd(ARG0) || p.dumping_fd(RC))
                                    dump_syscall(capio, p, regs, "fd:%lld, addr:%s, flags:%s",
                                                 ARG0,
                                                 read_proc_sockaddr(pid, ARG1, ARG2).c_str(),
                                                 sock_flags2string(ARG3).c_str());
                                break;
                            case SYS_clone:
                                if (p.dumping)
                                    dump_syscall(capio, p, regs, "");
                                break;
                            case SYS_execve: {
                                bool was_dumping = p.dumping;
                                p.reset_process_name();
                                if (capio.quiet && p.dumping || was_dumping)  {
                                    // sys_execve	const char *filename	const char *const argv[]	const char *const envp[]
                                    dump_syscall_wo_endl(capio, p,regs, "%s", p.enter_args.c_str());
                                    dual_ostream &out = capio.out(p);
                                    out << "; path:";
                                    put_quoted(out, p.process_name);
                                    out << endl;
                                }
                                break;
                            }
                            case SYS_dup:
                                capio.dup_fd(p, ARG0, RC);
                                if (p.dumping_fd(ARG0) || p.dumping_fd(RC))
                                    dump_syscall(capio, p, regs, "fd:%lld", ARG0);
                                break;
                            case SYS_dup2:
                                capio.dup_fd(p, ARG0, ARG1);
                                if (p.dumping_fd(ARG0) || p.dumping_fd(RC))
                                    dump_syscall(capio, p, regs, "oldfd:%lld, newfd:%lld", ARG0, ARG1);
                                break;
                            case SYS_dup3:
                                capio.dup_fd(p, ARG0, ARG1);
                                if (p.dumping_fd(ARG0) || p.dumping_fd(RC))
                                    dump_syscall(capio, p, regs, "oldfd:%lld, newfd:%lld, flags:%s",
                                                 ARG0, ARG1, o_flags2string(ARG2).c_str());
                                break;
                            case SYS_close:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld", ARG0);
                                p.close_fd(ARG0);
                                break;
                            case SYS_mmap:
                                if (ARG4 >= 0) {
                                    if (p.dumping_fd(ARG4))
                                        dump_syscall(capio, p, regs,
                                                     "addr:0x%llx, length:%lld, prot:%s, flags:%s, fd:%lld, offset:%lld",
                                                     ARG0, ARG1,
                                                     prot_flags2string(ARG2).c_str(),
                                                     map_flags2string(ARG3).c_str(), ARG4, ARG5);
                                }
                                break;
                            case SYS_flock:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, operation:%s", ARG0,
                                                 lock_flags2string(ARG1).c_str());
                                break;
                            case SYS_fsync:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld", ARG0);
                                break;
                            case SYS_fdatasync:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld", ARG0);
                                break;
                            case SYS_ftruncate:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, length:%lld", ARG0, ARG1);
                                break;
                            case SYS_getdents:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, dirents:[...]", ARG0);
                                break;
                            case SYS_getdents64:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, dirents:[...]", ARG0);
                                break;
                            case SYS_fchdir:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld", ARG0);
                                break;
                            case SYS_fchmod:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, mode:0%llo", ARG0, ARG1);
                                break;
                            case SYS_fchown:
                                if (p.dumping  && p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, user:%lld, group:%lld", ARG0, ARG1, ARG2);
                                break;
                            case SYS_fstatfs:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, buf:...", ARG0);
                                break;
                            case SYS_readahead:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, offset:%lld, count:%lld", ARG0, ARG1, ARG2);
                                break;
                            case SYS_fsetxattr:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, ...", ARG0);
                                break;
                            case SYS_fgetxattr:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, ...", ARG0);
                                break;
                            case SYS_fremovexattr:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, ...", ARG0);
                                break;
                            case SYS_fadvise64:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, offset:%lld, len:%lld, advice:%s",
                                                 ARG0, ARG1, ARG2,
                                                 posix_fadv_flags2string(ARG3).c_str());
                                break;
                            case SYS_inotify_init:
                                if (p.dumping_fd(RC))
                                    dump_syscall(capio, p, regs, "");
                                break;
                            case SYS_inotify_init1:
                                if (p.dumping_fd(RC))
                                    dump_syscall(capio, p, regs, "flags:%s",
                                                 in_init1_flags2string(ARG0).c_str());
                                break;
                            case SYS_inotify_add_watch:
                                 if (p.dumping_fd(ARG0))
                                     dump_syscall(capio, p, regs, "fd:%lld, path:%s, mask:%s",
                                                  ARG0,
                                                  read_proc_c_string_quoted(pid, ARG1).c_str(),
                                                  in_flags2string(ARG2).c_str());
                                 break;
                            case SYS_inotify_rm_watch:
                                if (p.dumping_fd(ARG0))
                                    dump_syscall(capio, p, regs, "fd:%lld, wd:%lld", ARG0, ARG1);
                                 break;
                            case SYS_openat:
                                p.close_fd(RC);
                                if (p.dumping_fd(ARG0) || p.dumping_fd(RC))
                                    dump_syscall(capio, p, regs, "dfd:%lld, path:%s, flags:%s, mode:0%03llo",
                                                 ARG0,
                                                 read_proc_c_string_quoted(pid, ARG1).c_str(),
                                                 o_flags2string(ARG2).c_str(),
                                                 ARG3);
                                 break;
                            case SYS_splice:
                                if (p.dumping_fd(ARG0) || p.dumping_fd(ARG2))
                                    dump_syscall(capio, p, regs,
                                                 "fd_in:%lld, off_in:%s, fd_out:%lld, off_out:%s, len:%lld, flags:%s",
                                                 ARG0,
                                                 read_proc_off_t(pid, ARG1).c_str(),
                                                 ARG2,
                                                 read_proc_off_t(pid, ARG3).c_str(),
                                                 ARG4,
                                                 splice_flags2string(ARG5).c_str());
                                break;
                            case SYS_tee:
                                if (p.dumping_fd(ARG0) || p.dumping_fd(ARG1))
                                    dump_syscall(capio, p, regs, "fdin:%lld, fdout:%lld, len:%lld, flags:%s",
                                                 ARG0, ARG1, ARG2,
                                                 splice_flags2string(ARG3).c_str());
                                break;
                            default:
                                debug(1, "syscall %d!", OP);
                                if ((OP < 0) && (OP > SYSCALL_LAST)) {
                                    handle_syscall_unexpected(capio, p, regs);
                                }
                                else {
                                    syscalls[OP].handler(capio, p, regs);
                                }
                                //if (!capio.quiet && p.dumping && p.dumping_fd(ARG0)) 
                                //    out << "#" << pid << " __ unsupported system call__(" << OP << ") = " << RC << endl << flush;
                                break;
                            }
                        }
                    }
                    else {
                        p.sigcall_exiting = true;
                        ptrace(PTRACE_GETREGS, pid, NULL, &p.enter_regs);
                        struct user_regs_struct &regs = p.enter_regs;

                        debug(4, "ENTER pid: %d, orig_rax: %lld, rax: %lld, rdi: %lld, rsi: %lld, rdx: %lld, r10: %lld, r9: %lld, r8: %lld",
                              pid, OP, RC, ARG0, ARG1, ARG2, ARG3, ARG4, ARG5);

                        switch(OP) {
                        case SYS_execve:
                            /* execve arguments are missing once execve returns so, we save them here */
                            stringstream ss;
                            ss << "name:" << read_proc_c_string_quoted(pid, ARG0)
                               << ", args:" << read_proc_array_c_string_quoted(pid, ARG1)
                               << ", env:" << read_proc_array_c_string_quoted(pid, ARG2);
                            p.enter_args = ss.str();
                            break;
                        }
                    }
                }
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                continue;
            }
            else if (WIFSIGNALED(wstatus)) {
                debug(1, "Pid %d terminated by signal %d", pid, WTERMSIG(wstatus));
            }
            else if (WIFEXITED(wstatus)) {
                debug(1, "Pid %d terminated with code %d", pid, WEXITSTATUS(wstatus));
            }
            else {
                debug(1, "Doing nothing for pid %d - wstatus: %d", pid, wstatus);
                continue;
            }
#ifdef WITH_PERL
            if (pp->out)
                fd_close_perl(*pp->out);
#endif
            processes.erase(pid);
            delete pp;
        }
    }

#ifdef WITH_PERL
    if (perl_flag)
        shutdown_perl();
    perl_sys_term();
#endif

}
