
const unsigned char* read_proc_mem(pid_t pid, long long mem, size_t len);
void fatal(const char *msg);

struct dual_ostream : ostream {
private:
    __gnu_cxx::stdio_filebuf<char> *filebuf;
    static int ensure_open(const string &fn) {
        int fd = open(fn.c_str(), O_CREAT|O_CLOEXEC|O_APPEND|O_TRUNC|O_WRONLY, 0666);
        if (fd < 0) fatal(fn.c_str());
        return fd;
    }

    dual_ostream(int fd_, __gnu_cxx::stdio_filebuf<char> *filebuf_) :
        fd(fd_),
        filebuf(filebuf_),
        ostream(filebuf_) {}
public:
    int fd;
    dual_ostream(int fd_) : dual_ostream(fd_, new __gnu_cxx::stdio_filebuf<char>(fd_, std::ios::out)) {}
    dual_ostream(string &filename) : dual_ostream(ensure_open(filename.c_str())) {}
    ~dual_ostream() {
        this->flush();
        cerr << string("dual_ostream destructor for ") + to_string((long long)this) + " called, fd: " + to_string(fd) <<endl;
    }

    operator int() { return fd; }
};

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

    Process(pid_t pid);
    ~Process();

    FDGroup *fdgroup(int fd);
    void dup_fd(int oldfd, int newfd);
    void close_fd(int fd);
    bool dumping_fd(int fd);
    void reset_process_name();
    const string &fd_path(int fd);
    dual_ostream *out;
private:
    unordered_map<int,FDGroup*> fdgroups;
};

