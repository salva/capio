
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <syscall.h>
#include <fnmatch.h>
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
static void dump_hex(ostream &out, pid_t pid, int fd, size_t len, int op, const unsigned char *data) {
    int dir = (op == 1 ? '>' : '<');
    int lines = (len + LINELEN - 1) / LINELEN;
    if (lines == 0) lines = 1;
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
            if (off < len)
                out.put(isprint(data[off]) ? data[off] : '.');
            else
                out << ' ';
        }

        out << " ";
        out.put(dir);
        if (i == 0)
            out << " pid: " << pid << ", fd: " << fd << ", len: " << len;
        out << endl << flush;
    }
}

static void
dump_quoted(ostream &out, pid_t pid, int fd, size_t len, int op, const unsigned char *data, bool breaks) {
    out.put(op == 1 ? '>' : '<');
    out << " pid: " << pid << ", fd: " << fd << ", len: " << len << endl;
    if (len) {
        out.put('"');
        for (int i = 0; i < len; i++) {
            int c = data[i];
            switch(c) {
            case '\0':
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
                    out << "\"" << endl << "\"";
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

        out.put('"');
        out << endl << flush;
    }
}

static void
dump_raw(ostream &out, size_t len, const unsigned char *data) {
    out.write(reinterpret_cast<const char *>(data), len);
    out << flush;
}

static void dump(ostream &out, int format, pid_t pid, int fd, size_t len, int op, const unsigned char *data) {
    switch (format) {
    case 'x':
        dump_hex(out, pid, fd, len, op, data);
        break;
    case 'q':
        dump_quoted(out, pid, fd, len, op, data, false);
        break;
    case 'n':
        dump_quoted(out, pid, fd, len, op, data, true);
        break;
    case 'r':
        dump_raw(out, len, data);
        break;
    default:
        debug(1, "Format %c not implemented yet", format);
        break;
    }
}

static unsigned char *
get_buffer(size_t len) {
    static unsigned char *buffer = NULL;
    static unsigned char buffer_size = 0;

    if (len > buffer_size) {
        buffer = (unsigned char *)realloc(buffer, len);
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
        buffer = get_buffer(len_long * sizeof(long));

        for (i = 0; i < len_long; i++)
            ((long*)buffer)[i] = ptrace(PTRACE_PEEKTEXT, pid, mem + i * sizeof(long), NULL);

        return buffer + offset;
    }
    return (const unsigned char*)"";
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

int
main(int argc, char *argv[]) {
    int opt;
    int fd;
    pid_t pid;
    out = &cout;
    while ((opt = getopt(argc, argv, "o:m:p:n:l:fd")) != -1) {
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
                              pid, regs.orig_rax, regs.rax, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r9, regs.r8);

                        long long rc = regs.rax;
                        if (rc >= 0) {
                            long long op = regs.orig_rax;
                            switch(op) {
                            case SYS_read:
                            case SYS_write:
                            {
                                debug(1, "write or read: %d", op);
                                int fd = regs.rdi;
                                if (p.dumping && (!fds || (*fds)[fd])) {
                                    long long mem = regs.rsi;
                                    size_t len = rc;
                                    debug(5, "dumping %d bytes for fd %d", len, fd);
                                    const unsigned char *data = read_proc_mem(pid, mem, len);
                                    dump(*out, format, pid, fd, len, op, data);
                                }
                                else {
                                    debug(4, "skipping process %d\n", pid);
                                }
                                break;
                            }
                            case SYS_clone:
                                debug(1, "clone!");
                                break;
                            case SYS_execve:
                                debug(1, "exec!");
                                reset_process_name(p);
                                break;
                            default:
                                break;
                            }
                        }
                    }
                    else {
                        p.sigcall_exiting = true;
                        ptrace(PTRACE_GETREGS, pid, NULL, &p.enter_regs);
                        struct user_regs_struct &regs = p.enter_regs;
                        debug(4, "ENTER pid: %d, orig_rax: %lld, rax: %lld, rdi: %lld, rsi: %lld, rdx: %lld, r10: %lld, r9: %lld, r8: %lld",
                              pid, regs.orig_rax, regs.rax, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r9, regs.r8);
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