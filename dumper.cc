#include "capio.h"
#include "syscall.h"
#include "regs.h"
#include "memory.h"
#include "flags.h"
#include "util.h"

using namespace std;

void
dump_syscall_start(Capio &c, Process &p, struct user_regs_struct &regs) {
    dual_ostream &out = c.out(p);
    out << "# ";
    if (c.dump_children)
        out << p.pid << " ";
    out << syscalls[OP].name;
}

void
dump_syscall_argsv(Capio &c, Process &p, const char *fmt, va_list args) {
    dual_ostream &out = c.out(p);
    size_t available = 4096;
    while (1) {
        va_list args_cp;
        va_copy(args_cp, args);
        char *buff = (char *)get_buffer(available);
        size_t required = vsnprintf(buff, available, fmt, args_cp);
        va_end(args_cp);
        if (required < available) {
            out << "(" << buff << ")";
            break;
        }
        available = required + 10;
    }
}

void
dump_syscall_end(Capio &c, Process &p, struct user_regs_struct &regs) {
    dual_ostream &out = c.out(p);
    if (RC < 0)
        out << " = -1, errno:" << e_flags2string(-RC);
    else
        out << " = " << RC;
}

void
dump_syscall_wo_endl(Capio &c, Process &p, struct user_regs_struct &regs, const char *fmt ...) {
    dump_syscall_start(c, p, regs);
    va_list args;
    va_start(args, fmt);
    dump_syscall_argsv(c, p, fmt, args);
    va_end(args);
    dump_syscall_end(c, p, regs);
}

void
dump_syscall(Capio &c, Process &p, struct user_regs_struct &regs, const char *fmt ...) {
    if (!c.quiet) {
        dump_syscall_start(c, p, regs);
        va_list args;
        va_start(args, fmt);
        dump_syscall_argsv(c, p, fmt, args);
        va_end(args);
        dump_syscall_end(c, p, regs);
        c.out(p) << endl;
    }
}

void
dump_syscall_unimplemented(Capio &c, Process &p, struct user_regs_struct &regs) {
    if (!c.quiet) {
        dump_syscall_start(c, p, regs);
        dump_syscall_end(c, p, regs);
        c.out(p) << "; unimplemented" << endl;
    }
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

void
dump_mem(dual_ostream &out, char format, bool writting, const unsigned char *data, size_t len) {
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
    case '0':
        break;
    default:
        debug(1, "Format %c not implemented yet", format);
        break;
    }
}

void
dump_io(Capio &c, Process &p, struct user_regs_struct &regs, long long mem, size_t len) {
    dual_ostream &out = c.out(p);
    bool writting = syscalls[OP].writes();
    const unsigned char *data = read_proc_mem(p.pid, mem, len);
    dump_mem(out, c.format, writting, data, len);
#ifdef WITH_PERL
    if (perl_flag)
        dump_perl(out, p, ARG0, syscalls[OP].name, RC, writting, data, len);
#endif
}

void
dump_iov(Capio &c, Process &p, struct user_regs_struct &regs, long long mem, long long len) {
    size_t remaining = RC;
    auto vec = (struct iovec *)mem;
    for (size_t i = 0; remaining && i < len; i++) {
        struct iovec iov;
        read_proc_struct(p.pid, (long long)(vec + i), sizeof(iov), &iov);
        size_t chunk = ((remaining > iov.iov_len) ? iov.iov_len : remaining);
        dump_io(c, p, regs, mem, len);
        remaining -= chunk;
    }
}


