
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
#include <linux/limits.h>

#include <bits/stdc++.h>

using namespace std;

static int debug_level = 0;

static void
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

struct Process {
    pid_t pid;
    bool dumping;
    bool sigcall_exiting;
    string *process_name;
    struct user_regs_struct enter_regs;
    Process(pid_t pid = -1)
        : pid(pid), process_name(0),
          dumping(true), sigcall_exiting(false) {
        debug(4, "New process structure with pid %d", pid);
    }
    ~Process() {
        delete process_name;
    }
};

static void
fatal(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
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
put_quoted(ostream &out, const unsigned char *data, size_t len, bool breaks = false, string prefix = "", string quote = "\"") {
    out << prefix << quote;
    for (size_t i = 0; i < len; i++) {
        int c = data[i];
        switch(c) {
        case '\0':
            out << "\\0";
            break;
        case '\a':
            out << "\\a";
            break;
        case '\b':
            out << "\\b";
            break;
        case '\t':
            out << "\\t";
            break;
        case '\n':
            out << "\\n";
            if (breaks && (len - i > 1))
                out << quote << endl << prefix << quote;
            break;
        case '\v':
            out << "\\v";
            break;
        case '\f':
            out << "\\f";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\\':
            out << "\\\\";
            break;
        default:
            if (isprint(c)) {
                out.put(c);
            }
            else {
                char hex[10];
                sprintf(hex, "\\x%02x", c);
                out << hex;
            }
        }
    }
    out << quote;
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

static void*
get_buffer(size_t len) {
    static void *buffer = NULL;
    static size_t buffer_size = 0;

    if (len > buffer_size) {
        buffer = realloc(buffer, len);
        if (!buffer) fatal(NULL);
    }
    return buffer;
}

static const unsigned char *
read_proc_mem(pid_t pid, long long mem, size_t len) {
    if (len) {
        size_t i, offset, len_long;
        unsigned char *buffer;

        offset = mem & (sizeof(long) - 1);
        mem &= ~(sizeof(long) - 1);
        len += offset;
        len_long = (len + sizeof(long) - 1) / sizeof(long);
        buffer = (unsigned char *)get_buffer(len_long * sizeof(long));

        for (i = 0; i < len_long; i++)
            ((long*)buffer)[i] = ptrace(PTRACE_PEEKTEXT, pid, mem + i * sizeof(long), NULL);

        return buffer + offset;
    }
    return (const unsigned char*)"";
}

static void dump_mem(ostream &out, int format, bool writting, pid_t pid, long long mem, size_t len) {
    const unsigned char *data = read_proc_mem(pid, mem, len);
    switch (format) {
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
    default:
        debug(1, "Format %c not implemented yet", format);
        break;
    }
}

static string
read_proc_string_quoted(pid_t pid, long long mem, size_t len) {
    stringstream ss;
    if (mem) {
        const unsigned char *data = read_proc_mem(pid, mem, len);
        put_quoted(ss, data, len);
        return ss.str();
    }
    return "NULL";
}

static string
read_proc_c_string_quoted(pid_t pid, long long mem, size_t maxlen = 16384) {
    if (mem) {
        stringstream ss;
        ss << "\"";
        while (maxlen) {
            size_t chunk = 256 - (mem & 255);
            if (chunk > maxlen) chunk = maxlen;
            const unsigned char *data = read_proc_mem(pid, mem, chunk);
            int len = strnlen((const char*)data, chunk);
            put_quoted(ss, data, len, false, "", "");
            if (len < chunk)
                break;
            mem += chunk;
            maxlen -= chunk;
        }
        ss << "\"";
        return ss.str();

    }
    return "NULL";
}

static void
read_proc_struct(pid_t pid, long long mem, size_t len, void *to) {
    const unsigned char *data = read_proc_mem(pid, mem, len);
    memcpy(to, data, len);
}

static string *
process_name(pid_t pid) {
    string path = "/proc/" + to_string(pid) + "/exe";
    char buffer[PATH_MAX+2];
    size_t len = readlink(path.c_str(), buffer, PATH_MAX);
    if (len < 0) {
        fprintf(stderr, "Warning: unable to resolve process name for PID %d\n", pid);
        return NULL;
    }
    buffer[len] = '\0';
    return new string(buffer);
}

static unordered_map<pid_t, Process> processes;
static unordered_map<int, bool> *fds;
static string *name_pattern = NULL;
static bool dump_children = false;
static char format = 'x';
static ostream *out;
static bool quiet;

static void
reset_process_name(Process &p) {
    pid_t pid = p.pid;
    if (p.process_name)
        delete p.process_name;
    string *pn = p.process_name = process_name(pid);
    const char *pn_c_str = (pn ? pn->c_str() : NULL);
    debug(2, "process name for pid %d is %s\n", pid, pn_c_str);
    p.dumping = !name_pattern ||
        (fnmatch(name_pattern->c_str(), pn_c_str, FNM_EXTMATCH) == 0);
}

static long long
syscall_op(struct user_regs_struct &regs) { return regs.orig_rax; }
static long long
syscall_rc(struct user_regs_struct &regs) { return regs.rax; }
static long long
syscall_arg0(struct user_regs_struct &regs) { return regs.rdi; }
static long long
syscall_arg1(struct user_regs_struct &regs) { return regs.rsi; }
static long long
syscall_arg2(struct user_regs_struct &regs) { return regs.rdx; }
static long long
syscall_arg3(struct user_regs_struct &regs) { return regs.r10; }
static long long
syscall_arg4(struct user_regs_struct &regs) { return regs.r8; }
static long long
syscall_arg5(struct user_regs_struct &regs) { return regs.r9; }

#define OP (syscall_op(regs))
#define RC (syscall_rc(regs))
#define ARG0 (syscall_arg0(regs))
#define ARG1 (syscall_arg1(regs))
#define ARG2 (syscall_arg2(regs))
#define ARG3 (syscall_arg3(regs))
#define ARG4 (syscall_arg4(regs))
#define ARG5 (syscall_arg5(regs))

static bool
dumping_fd(int fd) { return ((fd >= 0) && (!fds || (*fds)[fd])); }

static void
dump_syscall(ostream &out, pid_t pid, const char *name, long long rc, const char *fmt ...) {
    if (!quiet) {
        out << "# ";
        if (dump_children)
            out << pid << " ";
        out << name << "(";
        size_t available = 4096;
        while (1) {
            char *buff = (char *)get_buffer(available);
            va_list ap;
            va_start(ap, fmt);
            size_t required = vsnprintf(buff, available, fmt, ap);
            va_end(ap);
            if (required < available) {
                out << buff;
                break;
            }
            available = required + 10;
        }
        out << ") = " << rc << endl;
    }
}

int
main(int argc, char *argv[]) {
    int opt;
    int fd;
    pid_t pid;
    out = &cout;
    while ((opt = getopt(argc, argv, "o:m:p:n:l:fdq")) != -1) {
        switch (opt) {
        case 'p':
            pid = atol(optarg);
            if (ptrace (PTRACE_ATTACH, pid, NULL, NULL) < 0)
                fatal("Unable to trace process");
            processes[pid] = Process();
            break;
        case 'n':
            name_pattern = new string(optarg);
            break;
        case 'f':
            dump_children = true;
            break;
        case 'd':
            debug_level++;
            break;
        case 'l':
            fd = atol(optarg);
            if (!fds)
                fds = new unordered_map<int, bool>();
            (*fds)[fd] = true;
            break;
        case 'm':
            if (strchr("xqrn", optarg[0]) && optarg[1] == '\0') {
                format = optarg[0];
            }
            else
                fatal("Bad format specifier");
            break;
        case 'o':
            out = new ofstream(optarg);
            break;
        case 'q':
            quiet = true;
            break;
        default:
            fprintf(stderr, "Usage: %s -p PID [-p PID1 [...]]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

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
        processes[pid] = Process();
    }

    while (!processes.empty()) {
        int wstatus;
        pid_t pid = wait(&wstatus);
        if (pid > 0) {
            Process &p = processes[pid];
            if (p.pid == -1) {
                debug(1, "New process with pid %d found", pid);
                p.pid = pid;
                int options = PTRACE_O_TRACESYSGOOD;
                if (dump_children)
                    options |= PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
                if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) < 0)
                    debug(1, "Unable to set ptrace options to %d for pid %d", options, pid);
                reset_process_name(p);
                debug(4, "Structure initilized");
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

                        if (RC >= 0) {
                            bool writting = false;
                            bool dumping = p.dumping;
                            switch(OP) {
                            case SYS_write:
                                writting = true;
                            case SYS_read:
                                if (p.dumping && dumping_fd(ARG0)) {
                                    dump_syscall(*out, pid,
                                                 (writting ? "write" : "read"),
                                                 RC, "fd:%lld", ARG0);
                                    dump_mem(*out, format, writting, pid, ARG1, RC);
                                }
                                break;
                            case SYS_sendto:
                                writting = true;
                            case SYS_recvfrom:
                                if (p.dumping && dumping_fd(ARG0)) {
                                    dump_syscall(*out, pid,
                                                 (writting ? "sendto" : "recvfrom"),
                                                 RC, "fd:%lld, ...", ARG0);
                                    dump_mem(*out, format, writting, pid, ARG1, RC);
                                }
                                break;
                            case SYS_open:
                                if (p.dumping && dumping_fd(RC))
                                    dump_syscall(*out, pid, "open", RC, "filename:%s, flags:%lld, mode:%lld",
                                                 read_proc_c_string_quoted(pid, (long long)ARG0).c_str(), ARG1, ARG2);
                                break;
                            case SYS_bind:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "bind", RC, "fd:%lld", ARG0);
                                break;
                            case SYS_listen:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "listen", RC, "fd:%lld, backlog:%lld", ARG0, ARG1);
                                break;
                            case SYS_sendmsg:
                                writting = true;
                            case SYS_recvmsg:
                                if (p.dumping && dumping_fd(ARG0)) {
                                    struct msghdr msg;
                                    read_proc_struct(pid, ARG1, sizeof(msg), (void*)&msg);
                                    dump_syscall(*out, pid,
                                                 (writting ? "sendmsg" : "recvmsg"),
                                                 RC,
                                                 "fd:%lld, name:%s, iovlen:%lld, control:%s",
                                                 ARG0,
                                                 read_proc_string_quoted(pid, (long long)msg.msg_name,
                                                                         msg.msg_namelen).c_str(),
                                                 msg.msg_iovlen,
                                                 read_proc_string_quoted(pid, (long long)msg.msg_control,
                                                                         msg.msg_controllen).c_str());
                                    size_t remaining = RC;
                                    for (size_t i = 0; remaining && i < msg.msg_iovlen; i++) {
                                        struct iovec iov;
                                        read_proc_struct(pid, (long long)(msg.msg_iov + i), sizeof(iov), &iov);
                                        size_t chunk = ((remaining > iov.iov_len) ? iov.iov_len : remaining);
                                        dump_mem(*out, format, writting, pid, (long long)iov.iov_base, chunk);
                                        remaining -= chunk;
                                    }
                                }
                                break;
                            case SYS_shutdown:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "shutdown", RC, "fd:%lld, how:%lld", ARG0, ARG1);
                                break;
                            case SYS_pwrite64:
                                writting = true;
                            case SYS_pread64:
                                if (p.dumping && dumping_fd(ARG0)) {
                                    dump_syscall(*out, pid,
                                                 (writting ? "pwrite" : "pread"),
                                                 RC, "fd:%lld, pos:%lld", ARG0, ARG3);
                                    dump_mem(*out, format, writting, pid, ARG1, RC);
                                }
                                break;
                            case SYS_writev:
                                writting = 1;
                            case SYS_readv:
                                if (p.dumping && dumping_fd(ARG0)) {
                                    dump_syscall(*out, pid,
                                                 (writting ? "writev" : "readv"),
                                                 RC, "fd:%lld", ARG0);
                                    size_t remaining = RC;
                                    struct iovec *vec = (struct iovec *)ARG2;
                                    for (size_t i = 0; remaining && i < ARG3; i++) {
                                        struct iovec iov;
                                        read_proc_struct(pid, (long long)(vec + i), sizeof(iov), &iov);
                                        size_t chunk = ((remaining > iov.iov_len) ? iov.iov_len : remaining);
                                        dump_mem(*out, format, writting, pid, (long long)iov.iov_base, chunk);
                                        remaining -= chunk;
                                    }
                                }
                                break;
                            case SYS_pipe:
                                if (p.dumping) {
                                    int filedes[2];
                                    read_proc_struct(pid, (long long)ARG0, sizeof(filedes), filedes);
                                    if (dumping_fd(filedes[0]) || dumping_fd(filedes[1]))
                                        dump_syscall(*out, pid, "pipe", RC, "fds:[%d, %d]", filedes[0], filedes[1]);
                                }
                                break;
                            case SYS_socketpair:
                                if (p.dumping) {
                                    int usockvec[2];
                                    read_proc_struct(pid, (long long)ARG3, sizeof(usockvec), usockvec);
                                    if (dumping_fd(usockvec[0]) || dumping_fd(usockvec[1]))
                                        dump_syscall(*out, pid, "socketpair", RC, "fds:[%d, %d]", usockvec[0], usockvec[1]);
                                }
                                break;
                            case SYS_sendfile:
                                if (p.dumping && (dumping_fd(ARG0) || dumping_fd(ARG1)))
                                    dump_syscall(*out, pid, "sendfile", RC,
                                                 "out_fd:%lld, in_fd:%lld, offset:%lld -- data not available)",
                                                 ARG0, ARG1, ARG2);
                                break;
                            case SYS_socket:
                                if (p.dumping && dumping_fd(RC))
                                    dump_syscall(*out, pid, "socket", RC, "");
                                break;
                            case SYS_connect:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "connect", RC, "fd:%lld", ARG0);
                                break;
                            case SYS_accept:
                                if (p.dumping && (dumping_fd(ARG0) || dumping_fd(RC)))
                                    dump_syscall(*out, pid, "accept", RC, "fd:%lld", ARG0);
                                break;
                            case SYS_clone:
                                if (p.dumping)
                                    dump_syscall(*out, pid, "clone", RC, "");
                                break;
                            case SYS_execve: {
                                bool was_dumping = p.dumping;
                                reset_process_name(p);
                                if (p.dumping || was_dumping)
                                    dump_syscall(*out, pid, "execve", RC, "name:%s",
                                                 (p.process_name ? p.process_name->c_str() : "*unknown*"));
                                break;
                            }
                            case SYS_dup:
                                if (p.dumping && (dumping_fd(ARG0) || dumping_fd(RC)))
                                    dump_syscall(*out, pid, "dup", RC, "fd:%lld", ARG0);
                                break;
                            case SYS_dup2:
                                if (p.dumping && (dumping_fd(ARG0) || dumping_fd(RC)))
                                    dump_syscall(*out, pid, "dup2", RC, "oldfd:%lld, newfd:%lld", ARG0, ARG1);
                                break;
                            case SYS_dup3:
                                if (p.dumping && (dumping_fd(ARG0) || dumping_fd(RC)))
                                    dump_syscall(*out, pid, "dup3", RC, "oldfd:%lld, newfd:%lld", ARG0, ARG1);
                                break;
                            case SYS_close:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "close", RC, "fd:%lld", ARG0);
                                break;
                            case SYS_mmap:
                                if (p.dumping && dumping_fd(ARG4))
                                    dump_syscall(*out, pid, "mmap", RC, "fd:%lld", ARG4);
                                break;
                            case SYS_flock:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "flock", RC, "fd:%lld, cmd:%lld", ARG0, ARG1);
                                break;
                            case SYS_fsync:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fsync", RC, "fd:%lld", ARG0);
                                break;
                            case SYS_fdatasync:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fdatasync", RC, "fd:%lld", ARG0);
                                break;
                            case SYS_ftruncate:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "ftruncate", RC, "fd:%lld, length:%lld", ARG0, ARG1);
                                break;
                            case SYS_getdents:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "getdents", RC, "fd:%lld, dirents:[...]", ARG0);
                                break;
                            case SYS_getdents64:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "getdents64", RC, "fd:%lld, dirents:[...]", ARG0);
                                break;
                            case SYS_fchdir:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fchdir", RC, "fd:%lld", ARG0);
                                break;
                            case SYS_fchmod:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fchmod", RC, "fd:%lld, mode:0%llo", ARG0, ARG1);
                                break;
                            case SYS_fchown:
                                if (p.dumping  && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fchown", RC, "fd:%lld, user:%lld, group:%lld", ARG0, ARG1, ARG2);
                                break;
                            case SYS_fstatfs:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fstatfs", RC, "fd:%lld, buf:...", ARG0);
                                break;
                            case SYS_readahead:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "readahead", RC, "fd:%lld, offset:%lld, count:%lld", ARG0, ARG1, ARG2);
                                break;
                            case SYS_fsetxattr:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fsetxattr", RC, "fd:%lld, ...", ARG0);
                                break;
                            case SYS_fgetxattr:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fgetxattr", RC, "fd:%lld, ...", ARG0);
                                break;
                            case SYS_fremovexattr:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fremovexattr", RC, "fd:%lld, ...", ARG0);
                                break;
                            case SYS_fadvise64:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "fadvise64", RC, "fd:%lld, offset:%lld, len:%lld, advice:%ldd",
                                                 ARG0, ARG1, ARG2, ARG3);
                                break;
                            case SYS_inotify_init:
                                if (p.dumping && dumping_fd(RC))
                                    dump_syscall(*out, pid, "inotify_init", RC, "");
                                break;
                            case SYS_inotify_add_watch:
                                 if (p.dumping && dumping_fd(ARG0))
                                     dump_syscall(*out, pid, "inotify_add_watch", RC, "fd:%lld, ..., mask:%lld", ARG0, ARG2);
                                 break;
                            case SYS_inotify_rm_watch:
                                if (p.dumping && dumping_fd(ARG0))
                                    dump_syscall(*out, pid, "inotify_rm_watch", RC, "fd:%lld, wd:%lld", ARG0, ARG1);
                                 break;
                            case SYS_openat:
                                if (p.dumping && (dumping_fd(ARG0) || dumping_fd(RC)))
                                    dump_syscall(*out, pid, "openat", RC, "dfd:%lld, ..., flags:%ldd, mode:%ldd",
                                                 ARG0, ARG2, ARG3);
                                 break;
                            case SYS_splice:
                                if (p.dumping && (dumping_fd(ARG0) || dumping_fd(ARG2)))
                                    dump_syscall(*out, pid, "splice", RC, "fd_in:%lld, ..., fd_out:%lld, len:%lld, flags:%lld",
                                                 ARG0, ARG2, ARG4, ARG5);
                                break;
                            case SYS_tee:
                                if (p.dumping && (dumping_fd(ARG0) || dumping_fd(ARG1)))
                                    dump_syscall(*out, pid, "tee", RC, "fdin:%lld, fdout:%lld, len:%lld, flags:%lld",
                                                 ARG0, ARG1, ARG2, ARG3);
                                break;
                            default:
                                //if (!quiet && p.dumping && dumping_fd(ARG0))
                                //    *out << "#" << pid << " __ unsupported system call__(" << OP << ") = " << RC << endl << flush;
                                debug(1, "syscall %d!", OP);
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
            processes.erase(pid);
        }
    }
}
