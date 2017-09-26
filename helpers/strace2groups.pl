use strict;
use warnings;

my %strace_name = qw(TD     TRACE_DESC
                     TF     TRACE_FILE
                     TI     TRACE_IPC
                     TN     TRACE_NETWORK
                     TP     TRACE_PROCESS
                     TS     TRACE_SIGNAL
                     TM     TRACE_MEMORY
                     TST    TRACE_STAT
                     TLST   TRACE_LSTAT
                     TFST   TRACE_FSTAT
                     TSTA   TRACE_STAT_LIKE
                     TSF    TRACE_STATFS
                     TFSF   TRACE_FSTATFS
                     TSFA   TRACE_STATFS_LIKE
                     NF     SYSCALL_NEVER_FAILS
                     SI     STACKTRACE_INVALIDATE_CACHE
                     SE     STACKTRACE_CAPTURE_ON_ENTER
                     CST    COMPAT_SYSCALL_TYPES);

my %group;

while (<>) {
    s/\s//g;
    if (my ($n, $data) = /^\[(\d+)\]=\{(.*?)\},?$/) {
        my ($args, $flags, $sys, $name) = split /,/, $data;
        $name =~ s/"//g;
        if ($flags ne '0') {
            my @flags = split /\|/, $flags;
            for my $flag (@flags) {
                my $sn = $strace_name{$flag};
                if ($sn =~ /TRACE_(.*)/) {
                    push @{$group{"strace_" . lc $1}}, $name;
                }
            }
        }
    }
    else {
        warn "$_ do not match!\n";
    }
}

use Data::Dumper;
warn Dumper(\%group)."\n"

