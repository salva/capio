#include <sys/ptrace.h>
#include <linux/capability.h>

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
read_proc_c_string(pid_t pid, long long mem, size_t maxlen) {
    if (mem) {
        stringstream ss;
        int start = mem & (sizeof(long) - 1);
        while (maxlen > 0) {
            union {
                unsigned char buffer[1];
                long buffer_long;
            };
            buffer_long = ptrace(PTRACE_PEEKTEXT, pid, mem - start, NULL);
            for (int i = start; maxlen-- && (i < sizeof(long)); i++) {
                if (buffer[i] == 0) break;
                ss.put(buffer[i]);
            }
            start = 0;
        }
        return ss.str();
    }
    return "";
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
    return "NULL";
}

string
read_proc_user_cap_header(pid_t pid, long long mem) {
    if (mem) {
        auto header = (struct __user_cap_header_struct *)read_proc_mem(pid, mem, sizeof(struct __user_cap_header_struct));
        return "{version:" + to_string(header->version) + ", pid:" + to_string(header->pid) + "}";
    }
    return "NULL";
}

string
read_proc_user_cap_data(pid_t pid, long long mem) {
    if (mem) {
        auto data = (struct __user_cap_data_struct *)read_proc_mem(pid, mem, sizeof(struct __user_cap_data_struct));
        return ("{effective:" + to_string(data->effective) +
                ", permitted:" + to_string(data->permitted) +
                ", inheritable:" + to_string(data->inheritable) + "}");
    }
    return "NULL";
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
read_proc_size_t(pid_t pid, long long mem) {
    if (mem) {
        auto data = (const size_t *)read_proc_mem(pid, mem, sizeof(size_t));
        return to_string(*data);
    }
    return "NULL";
}

string
read_proc_int(pid_t pid, long long mem) {
    if (mem) {
        auto data = (const int*)read_proc_mem(pid, mem, sizeof(int));
        return to_string(*data);
    }
    return "NULL";
}

string
read_proc_ulong(pid_t pid, long long mem) {
    if (mem) {
        auto data = (const unsigned long*)read_proc_mem(pid, mem, sizeof(unsigned long));
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
            if (i) ss << ", ";
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

string
read_proc_array_int(pid_t pid, long long mem, size_t items) {
    if (mem) {
        stringstream ss;
        ss << "[";
        int *ptr = (int *)mem;
        for (int i = 0; i < items; i++) {
            if (i) ss << ", ";
            ss << read_proc_int(pid, (long long)(ptr + i));
        }
        ss << "]";
        return ss.str();
    }
    return "NULL";
}

string
read_proc_sysctl_args(pid_t pid, long long mem) {
    if (mem) {
        struct __sysctl_args args;
        read_proc_struct(pid, mem, sizeof(args), &args);
        size_t oldlen = 0;
        if (args.oldlenp)
            read_proc_struct(pid, mem, sizeof(oldlen), &oldlen);

        stringstream ss;
        ss << "{name:" << read_proc_array_int(pid, (long long)args.name, args.nlen)
           << ", oldval:" << ((args.oldlenp && args.oldval)
                              ? read_proc_string_quoted(pid, (long long)args.oldval, oldlen)
                              : string("NULL"))
           << ", newval:" << read_proc_string_quoted(pid, (long long)args.newval, args.newlen)
           << "}";
        return ss.str();
    }
    return "NULL";
}

string
read_proc_timeval(pid_t pid, long long mem) {
    if (mem) {
        struct timeval tv;
        char buffer[60];
        read_proc_struct(pid, mem, sizeof(tv), &tv);
        sprintf(buffer, "%llu.%06llu", (unsigned long long)tv.tv_sec, (unsigned long long)tv.tv_usec);
        return buffer;
    }
    return "NULL";
}

string
read_proc_timespec(pid_t pid, long long mem) {
    if (mem) {
        struct timespec ts;
        char buffer[60];
        read_proc_struct(pid, mem, sizeof(ts), &ts);
        sprintf(buffer, "%llu.%09llu", (unsigned long long)ts.tv_sec, (unsigned long long)ts.tv_nsec);
        return buffer;
    }
    return "NULL";
}
