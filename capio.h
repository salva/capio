
#include <ext/stdio_filebuf.h>
#include <bits/stdc++.h>
#include <sys/user.h>

#include "dual_ostream.h"
#include "syscall_defs.h"

void debug(int level, const char *fmt...);
const unsigned char* read_proc_mem(pid_t pid, long long mem, size_t len);
void fatal(const char *msg);

struct FDGroup {
    std::forward_list<int> fds;
    bool dumping;
    std::string path;
    FDGroup(int fd, std::string path_);
    void add_fd(int fd);
    void rm_fd(int fd);
    bool empty();
};

struct Process {
    pid_t pid;
    bool initialized;
    bool dumping;
    bool sigcall_exiting;
    std::string process_name;
    std::string enter_args;
    struct user_regs_struct enter_regs;
    dual_ostream *out;

    Process(pid_t pid);
    ~Process();

    FDGroup *fdgroup(int fd);
    void dup_fd(int oldfd, int newfd);
    void close_fd(int fd);
    bool dumping_fd(int fd);
    void reset_process_name();
    const std::string &fd_path(int fd);
    std::string resolve_path(const std::string &path);

private:
    std::unordered_map<int,FDGroup*> fdgroups;
};

struct Capio {
    bool dump_children;
    bool quiet;
    bool multifile;
    bool dont_follow;
    char format;
    std::string *out_fn;
    dual_ostream *default_out;

    bool dumping_syscalls[SYSCALL_LAST+1];

    Capio() :
        format('\0'), dump_children(false), quiet(false),
        dont_follow(false), multifile(false),
        out_fn(NULL), default_out(NULL) {
        memset(dumping_syscalls, 0, sizeof(dumping_syscalls));
    }

    void enable_group(long long tag);
    void disable_group(long long tag);

    void enable_syscall(long long op);
    void disable_syscall(long long op);

    dual_ostream &out(Process &p);
    dual_ostream &out();

    void
    dup_fd(Process &p, int old_fd, int new_fd) {
        if (!dont_follow)
            p.dup_fd(old_fd, new_fd);
    }

    bool dumping(Process &p, long long op);
    bool dumping(Process &p, long long op, int fd1, int fd2 = -1);

    bool dumping_path(const std::string &path);
};
