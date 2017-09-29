#!/usr/bin/perl

use strict;
use warnings;
use YAML ();

my $make_handler = 0;

my $tbl = shift // 'docs/syscall_64.tbl';

my $out_cc = shift // 'syscall.cc';
my $out_handler_cc = shift // 'handler.cc';

my $out_h  = shift // 'syscall_defs.h';
my $out_yaml = shift // 'syscall.yaml';

open my $fh, '<', $tbl or die "$tbl: $!\n";

my %group = ( read  =>
              [qw(read pread64 readv preadv preadv2 recvfrom recvmsg recvmmsg)],

              write =>
              [qw(write pwrite64 writev pwritev pwritev2 sendto sendmsg sendmmsg vmsplice)],

              io =>
              [qw(%read %write sendfile splice tee)],

              desc =>
              [qw(%strace_desc)],

              process =>
              [qw(%strace_process)],

              default =>
              [qw(%desc %process)],

              unexpected => [], # this is filled automatically bellow

              strace_capture_on_enter =>
              [qw(execve exit exit_group execveat)],

              strace_desc =>
              [qw(read write open close fstat poll lseek mmap ioctl pread64 pwrite64 readv writev pipe select dup dup2 sendfile fcntl flock
                  fsync fdatasync ftruncate getdents fchdir creat fchmod fchown fstatfs readahead fsetxattr fgetxattr flistxattr
                  fremovexattr epoll_create getdents64 fadvise64 epoll_wait epoll_ctl inotify_init inotify_add_watch inotify_rm_watch openat
                  mkdirat mknodat fchownat futimesat newfstatat unlinkat renameat linkat symlinkat readlinkat fchmodat faccessat pselect6
                  ppoll splice tee sync_file_range vmsplice utimensat epoll_pwait signalfd timerfd_create eventfd fallocate timerfd_settime
                  timerfd_gettime signalfd4 eventfd2 epoll_create1 dup3 pipe2 inotify_init1 preadv pwritev perf_event_open fanotify_init
                  fanotify_mark name_to_handle_at open_by_handle_at syncfs setns finit_module renameat2 memfd_create kexec_file_load bpf
                  execveat userfaultfd copy_file_range preadv2 pwritev2 statx)],

              strace_file =>
              [qw(open stat lstat access execve truncate getcwd chdir rename mkdir rmdir creat link unlink symlink readlink chmod chown
                  lchown utime mknod uselib statfs pivot_root chroot acct mount umount2 swapon swapoff quotactl setxattr lsetxattr getxattr
                  lgetxattr listxattr llistxattr removexattr lremovexattr utimes inotify_add_watch openat mkdirat mknodat fchownat futimesat
                  newfstatat unlinkat renameat linkat symlinkat readlinkat fchmodat faccessat utimensat fanotify_mark name_to_handle_at
                  renameat2 execveat statx)],

              strace_fstat =>
              [qw(fstat newfstatat)],

              strace_fstatfs =>
              [qw(fstatfs)],

              strace_invalidate_cache =>
              [qw(mmap mprotect munmap brk mremap shmat execve shmdt remap_file_pages execveat pkey_mprotect)],

              strace_ipc =>
              [qw(shmget shmat shmctl semget semop semctl shmdt msgget msgsnd msgrcv msgctl semtimedop)],

              strace_lstat =>
              [qw(lstat)],

              strace_memory =>
              [qw(mmap mprotect munmap brk mremap msync mincore madvise shmat shmdt mlock munlock mlockall munlockall io_setup io_destroy
                  remap_file_pages mbind set_mempolicy get_mempolicy migrate_pages move_pages mlock2 pkey_mprotect)],

              strace_network =>
              [qw(sendfile socket connect accept sendto recvfrom sendmsg recvmsg shutdown bind listen getsockname getpeername socketpair
                  setsockopt getsockopt getpmsg putpmsg accept4 recvmmsg sendmmsg)],

              strace_process =>
              [qw(clone fork vfork execve exit wait4 arch_prctl exit_group waitid unshare rt_tgsigqueueinfo execveat)],

              strace_signal =>
              [qw(rt_sigaction rt_sigprocmask rt_sigreturn pause kill rt_sigpending rt_sigtimedwait rt_sigqueueinfo rt_sigsuspend
                  sigaltstack tkill tgkill signalfd signalfd4 rt_tgsigqueueinfo)],

              strace_stat =>
              [qw(stat)],

              strace_stat_like =>
              [qw(stat fstat lstat newfstatat statx)],

              strace_statfs =>
              [qw(statfs)],

              strace_statfs_like =>
              [qw(ustat statfs fstatfs)],


            );

sub _expand_group {
    my $k = shift;
    my $v = $group{$k} // [];
    my $i = @$v;
    while ($i-- > 0) {
        if ($v->[$i] =~ /^%(.*)/) {
            splice @$v, $i, 1, _expand_group($1);
        }
    }
    return @$v;
}

_expand_group($_) for keys %group;

my %grinv;
while (my ($k, $v) = each %group) {
    push @{$grinv{$_} //= []}, $k for @$v;
}

my %syscall;
my %handler = (handle_syscall_unexpected => 1);

my $max_n = -1;
while (<$fh>) {
    next if /^\s*(?:#.*)?$/;
    my ($n, $abi, $name, $entry) = split /\s+/, $_;

    $max_n = $n if $n > $max_n;

    my @groups = sort @{$grinv{$name} // []};

    my @flags = ($abi eq 'common' ? ('abi_64', 'abi_x32') : "abi_$abi");
    while ($entry =~ s|/([^/]+)||) {
        push @flags, $1;
    }

    push @flags, 'read' if grep $_ eq 'read', @groups;
    push @flags, 'write' if grep $_ eq 'write', @groups;

    my $handler = "handle_syscall__$name";
    $handler{$handler} = 1;

    $syscall{$n} = { n => $n,
                     name => $name,
                     entry => $entry,
                     handler => $handler,
                     flags => [sort @flags],
                     groups => [sort @{$grinv{$name} // []}] };
}

YAML::DumpFile($out_yaml, \%syscall);

open my $fh_cc, '>', $out_cc or die "$out_cc: $!";
open my $fh_h,  '>', $out_h  or die "$out_h: $!";

print $fh_h <<EOH;

#define SYSCALL_LAST $max_n

EOH

my $group_bit = 0;
for my $group (sort keys %group) {
    my $tag = "GROUP_" . uc $group;
    my $val = 1 << $group_bit++;
    print $fh_h <<EOH;
#define $tag $val
EOH
}

print $fh_cc <<EOH;
#include "syscall.h"
#include "$out_h"

EOH

for my $handler (sort keys %handler) {
    print $fh_cc <<EOH;
void $handler(Capio &c, Process &p, struct user_regs_struct &regs);
EOH
}

print $fh_cc <<EOCC;

struct syscall syscalls[] = {
EOCC

for my $n (0..$max_n) {
    if (my $sc = $syscall{$n}) {
        my @f = @{$sc->{flags}};
        my $flags = (@f ? join '|', map "SYSCALL_".uc($_), @f : '0');
        my @g =  @{$sc->{groups}};
        my $groups = (@g ? join '|', map "GROUP_".uc($_), @g : '0');
        print $fh_cc <<EOCC;
    { /* $n */ "$sc->{name}", $flags, $groups, $sc->{handler} },
EOCC
    }
    else {
        print $fh_cc <<EOCC;
    { /* $n */ "unexpected_$n", SYSCALL_UNEXPECTED, GROUP_UNEXPECTED, &handle_syscall_unexpected, },
EOCC
    }
}

print $fh_cc <<EOCC;
};

struct group groups[] = {
EOCC

for my $gr (sort keys %group) {
    my $tag = 'GROUP_'.uc $gr;
    print $fh_cc <<EOCC;
    { "$gr", $tag, },
EOCC
}

print $fh_cc <<EOCC;
    { 0, 0, },
};

EOCC

if ($make_handler) {
    open my $fh_handler_cc, '>', "$out_handler_cc.tmpl" or die "$out_handler_cc.tmpl: $!";

    print $fh_handler_cc <<EOCC;
#include "syscall.h"
#include "regs.h"

EOCC

    for my $handler (sort keys %handler) {
        print $fh_handler_cc <<EOCC;
void
$handler(Capio &c, Process &p, struct user_regs_struct &regs) {

}

EOCC
    }
}
