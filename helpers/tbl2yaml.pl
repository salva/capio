#!/usr/bin/perl

use strict;
use warnings;
use YAML ();

my $tbl = shift // 'docs/syscall_64.tbl';
my $out = shift // 'syscalls.yaml';

open my $fh, '<', $tbl or die "$tbl: $!\n";

my %group = ( read  => [qw(read pread64 readv preadv preadv2 recvfrom recvmsg recvmmsg)],
              write => [qw(write pwrite64 writev pwritev pwritev2 sendto sendmsg sendmmsg vmsplice)],
              io    => [qw(%read %write sendfile splice tee)],
              desc  => [qw(%io)] );

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

use Data::Dumper;
warn Dumper \%grinv;

my %out;

while (<$fh>) {
    next if /^\s*(?:#.*)?$/;
    my ($n, $abi, $name, $entry) = split /\s+/, $_;

    my @flags = ($abi eq 'common' ? ('abi-64', 'abi-x32') : "abi-$abi");
    while ($entry =~ s|/([^/]+)||) {
        push @flags, $1;
    }

    $out{sprintf "0x%04x", $n} = { name => $name,
                                   entry => $entry,
                                   flags => [sort @flags],
                                   groups => [sort @{$grinv{$name} // []}] };
}



#use Data::Dumper;
#warn Dumper(\@out);

YAML::DumpFile($out, \%out);
