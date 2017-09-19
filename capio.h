

struct FDGroup {
    std::forward_list<int> fds;
    bool dumping;
    string path;
    FDGroup(int fd, string path_);
    void add_fd(int fd);
    void rm_fd(int fd);
    bool empty();
};

struct Process {
    pid_t pid;
    bool initialized;
    bool dumping;
    bool sigcall_exiting;
    string process_name;
    string enter_args;
    struct user_regs_struct enter_regs;

    FDGroup *fdgroup(int fd);
    Process(pid_t pid);

    void dup_fd(int oldfd, int newfd);
    void close_fd(int fd);
    bool dumping_fd(int fd);
    void reset_process_name();
    const string &fd_path(int fd);
private:
    unordered_map<int,FDGroup*> fdgroups;
};

static const unsigned char*
read_proc_mem(pid_t pid, long long mem, size_t len);
