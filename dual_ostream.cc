#include "dual_ostream.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace std;

void fatal(const char *msg);

dual_ostream::dual_ostream(std::string &fn) {
    fd = open(fn.c_str(), O_CREAT|O_CLOEXEC|O_APPEND|O_TRUNC|O_WRONLY, 0666);
    if (fd < 0) fatal(fn.c_str());
    rdbuf(new  __gnu_cxx::stdio_filebuf<char>(fd, std::ios::out));
}
