#include <ext/stdio_filebuf.h>
#include <bits/stdc++.h>

struct dual_ostream : std::ostream {
private:
    int fd;
public:
    dual_ostream(int fd_) :
        fd(fd_) {
        rdbuf(new  __gnu_cxx::stdio_filebuf<char>(fd, std::ios::out));
    }
    dual_ostream(const std::string &fn);
    ~dual_ostream() {
        flush();
        delete rdbuf();
    }
    operator int() { return fd; }
};
