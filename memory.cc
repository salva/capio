#include <sys/ptrace.h>
#include "memory.h"
#include "util.h"
#include "sockaddr.h"

void fatal(const char *msg);

using namespace std;

void*
get_buffer(size_t len) {
    static void *buffer = NULL;
    static size_t buffer_size = 0;

    if (len > buffer_size) {
        buffer = realloc(buffer, len);
        if (!buffer) fatal(NULL);
    }
    return buffer;
}

const unsigned char *
read_proc_mem(pid_t pid, long long mem, size_t len) {
    if (len > 0) {
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

string
read_proc_string_quoted(pid_t pid, long long mem, size_t len) {
    stringstream ss;
    if (mem) {
        const unsigned char *data = read_proc_mem(pid, mem, len);
        put_quoted(ss, data, len);
        return ss.str();
    }
    return "NULL";
}

void*
read_proc_ptr(pid_t pid, long long mem) {
    const unsigned char *data = read_proc_mem(pid, mem, sizeof(void*));
    return ((void**)data)[0];
}

string
read_proc_c_string_quoted(pid_t pid, long long mem, size_t maxlen) {
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

size_t round_up_len(size_t len) {
    return ((len + sizeof(long) - 1) & ~(sizeof(long) - 1));
}

string
read_proc_sockaddr(pid_t pid, long long mem, size_t len) {
    if (mem) {
        auto data = (struct sockaddr *)read_proc_mem(pid, mem, len);
        return sockaddr2string(data, len);
    }
    else {
        return "NULL";
    }
}

string
read_proc_off_t(pid_t pid, long long mem) {
    if (mem) {
        auto data = (const off_t *)read_proc_mem(pid, mem, sizeof(off_t));
        return to_string(*data);
    }
    return "NULL";
}

string
read_proc_array_c_string_quoted(pid_t pid, long long mem) {
    if (mem) {
        stringstream ss;
        ss << "[";
        char **argv = (char **)mem;
        for (int i = 0;; i++) {
            void *arg = read_proc_ptr(pid, (long long)(argv + i));
            if (!arg) break;
            if (i > 0) ss << ", ";
            ss << read_proc_c_string_quoted(pid, (long long)arg);
        }
        ss << "]";
        return ss.str();
    }
    return "NULL";
}

void
read_proc_struct(pid_t pid, long long mem, size_t len, void *to) {
    const unsigned char *data = read_proc_mem(pid, mem, len);
    memcpy(to, data, len);
}
