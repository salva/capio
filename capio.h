
#include <ext/stdio_filebuf.h>
#include <bits/stdc++.h>
#include <sys/user.h>

#include "dual_ostream.h"

static void debug(int level, const char *fmt...);
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
private:
    std::unordered_map<int,FDGroup*> fdgroups;
};

struct Capio {
    bool dump_children;
    bool quiet;

    dual_ostream &out(Process &p);
    dual_ostream &out();


};
