#include <stdlib.h>
#include <unistd.h>
#include <linux/sysctl.h>
#include <bits/stdc++.h>

void *get_buffer(size_t len);
const unsigned char *read_proc_mem(pid_t pid, long long mem, size_t len);
std::string read_proc_string_quoted(pid_t pid, long long mem, size_t len);
void *read_proc_ptr(pid_t pid, long long mem);
std::string read_proc_c_string_quoted(pid_t pid, long long mem, size_t maxlen = 16384);
size_t round_up_len(size_t len);
std::string read_proc_sockaddr(pid_t pid, long long mem, size_t len);
std::string read_proc_int(pid_t pid, long long mem);
std::string read_proc_ulong(pid_t pid, long long mem);
std::string read_proc_off_t(pid_t pid, long long mem);
std::string read_proc_array_c_string_quoted(pid_t pid, long long mem);
void read_proc_struct(pid_t pid, long long mem, size_t len, void *to);
std::string read_proc_sysctl_args(pid_t pid, long long mem);
std::string read_proc_c_string(pid_t pid, long long mem, size_t maxlen = 16384);
