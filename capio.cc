
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
#include "syscall_defs.h"
#include "flags.h"
#include "sockaddr.h"
#include "util.h"
#include "regs.h"
#include "dumper.h"
#include "memory.h"
#include "syscall.h"
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
    return fdgroup(fd)->dumping;
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
Capio::enable_group(long long tag) {
    for (int i = 0; i <= SYSCALL_LAST; i++) {
        if (syscalls[i].groups & tag)
            dumping_syscalls[i] = true;
    }
}

void
Capio::disable_group(long long tag) {
    for (int i = 0; i <= SYSCALL_LAST; i++) {
        if (syscalls[i].groups & tag)
            dumping_syscalls[i] = false;
    }
}

void
Capio::enable_syscall(long long op) {
    if ((op >= 0) && (op <= SYSCALL_LAST))
        dumping_syscalls[op] = true;
}

void
Capio::disable_syscall(long long op) {
    if ((op >= 0) && (op <= SYSCALL_LAST))
        dumping_syscalls[op] = false;
}

bool
Capio::dumping(Process &p, long long op) {
    if ((op >= 0) && (op <= SYSCALL_LAST)) {
        if (dumping_syscalls[op]) {
            if (p.dumping)
                return true;
        }
    }
    return false;
}

bool
Capio::dumping(Process &p, long long op, int fd1, int fd2) {
    if (dumping(p, op)) {
        if (p.dumping_fd(fd1)) {
            if ((fd2 == -1) || p.dumping_fd(fd2))
                return true;
        }
    }
    return false;
}

bool
Capio::dumping_path(const string &path) {
    return (fn_patterns.empty() || match_fn_patterns(fn_patterns, path));
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
    vector<string> groups;

    while ((opt = getopt(argc, argv, "o:m:M:p:n:N:l:e:E:s:fdqFO")) != -1) {
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
        case 's':
            split_and_append(groups, optarg);
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

    if (groups.empty())
        groups.push_back("%default");

    for(auto const& group: groups) {
        const char *str = group.c_str();
        bool disable = false;
        if (str[0] == '!') {
            str++;
            disable = true;
        }
        if (str[0] == '%') {
            long long tag = group_lookup(str+1);
            if (disable)
                capio.disable_group(tag);
            else
                capio.enable_group(tag);
        }
        else {
            long long op = syscall_lookup(str);
            if (disable)
                capio.disable_syscall(op);
            else
                capio.enable_syscall(op);
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

                        debug(4,
                              "EXIT pid: %d, orig_rax: %lld, rax: %lld, rdi: %lld, "
                              "rsi: %lld, rdx: %lld, r10: %lld, r9: %lld, r8: %lld",
                              pid, OP, RC, ARG0, ARG1, ARG2, ARG3, ARG4, ARG5);

                        if (RC >= 0 || RC == -EINPROGRESS) {
                            debug(1, "syscall %d!", OP);
                            if ((OP < 0) && (OP > SYSCALL_LAST))
                                handle_syscall_unexpected(capio, p, regs);
                            else
                                syscalls[OP].handler(capio, p, regs);
                        }
                    }
                    else {
                        p.sigcall_exiting = true;
                        ptrace(PTRACE_GETREGS, pid, NULL, &p.enter_regs);
                        struct user_regs_struct &regs = p.enter_regs;

                        debug(4,
                              "ENTER pid: %d, orig_rax: %lld, rax: %lld, rdi: %lld, "
                              "rsi: %lld, rdx: %lld, r10: %lld, r9: %lld, r8: %lld",
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
