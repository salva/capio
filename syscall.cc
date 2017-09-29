#include "capio.h"
#include "syscall.h"
#include "syscall_defs.h"

long long
syscall_lookup(const char *name) {
    debug(0, "syscall_lookup(%s)", name);
    for (int i = 0; i <= SYSCALL_LAST; i++) {
        if (strcmp(name, syscalls[i].name) == 0)
            return i;
    }
    fatal("unable to resolve syscall name");
}

long long
group_lookup(const char *name) {
    for (int i = 0; groups[i].name; i++) {
        if (strcmp(name, groups[i].name) == 0)
            return groups[i].tag;
    }
    fatal("unable to resolve group name");
}
