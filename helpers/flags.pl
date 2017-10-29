#/usr/bin/perl

use strict;
use warnings;

use YAML ();
use feature qw(:all);
use Data::Dumper;

our $debug = 1;

my $from = shift // 'flags.yaml';
my $to_cc = shift // $from =~ s/(:?\.yaml)?$/.cc/r;
my $to_h = shift // $to_cc =~ s/(:?\.cc)?$/.h/r;

my $id = 1;

my $data = YAML::LoadFile($from) or die "invalid data in YAML file $from";

#$debug and warn Dumper($data) ."\n";

open my $out_cc, '>', $to_cc or die "$to_cc: $!";
open my $out_h, '>', $to_h or die "$to_h: $!";

for my $header (@{$data->{headers}}) {
    print $out_h <<EOH;
#include <$header>
EOH
}

print $out_h <<EOH;
#include <string>
EOH

print $out_cc <<EOCC;
#include "$to_h"
EOCC

for my $k (sort keys %{$data->{define}}) {
    print $out_cc <<EOCC;
#define $k $data->{define}{$k}
EOCC
}

my $groups = $data->{groups};
for my $name (sort keys %$groups) {

    print $out_h <<EOH;
std::string ${name}_flags2string(long long);
EOH
    print $out_cc <<EOCC;
std::string
${name}_flags2string(long long flags) {
    std::string s("");
EOCC
    my $group = $groups->{$name};
    my $exclusive = $group->{exclusive};
    if ($exclusive) {
        for my $exc (@$exclusive) {
            my $flags = $exc->{flags};
            my $mask_var = "mask".$id++;
            print $out_cc "    long long $mask_var = 0";
            for my $flag (@$flags) {
                my ($f, $opt) = $flag =~ /(.*?)(\?)?$/;
                if ($opt) {
                    print $out_cc <<EOCC;

#ifdef $f
|$f
#endif
EOCC
                } else {
                    print $out_cc "|$f";
                }
            }
            print $out_cc ";\n";

            for my $flag (@$flags) {
                my ($f, $opt) = $flag =~ /(.*?)(\?)?$/;
                print $out_cc <<EOCC if $opt;
#ifdef $f
EOCC
                print $out_cc <<EOCC;
    if ((flags & ($mask_var)) == $f)
        s += "$f|";
EOCC
                print $out_cc <<EOCC if $opt;
#endif
EOCC
            }
        }
    }
    my $flags = $groups->{$name}{flags};
    if ($flags) {
        for my $flag (@$flags) {
            my ($f, $opt) = $flag =~ /(.*?)(\?)?$/;
            print $out_cc <<EOCC if $opt;
#ifdef $f
EOCC
            print $out_cc <<EOCC;
    if ($f == 0) {
        if (flags == 0)
            s += "$f|";
    }
    else {
        if ((flags & $f) == $f)
            s += "$f|";
    }
EOCC
            print $out_cc <<EOCC if $opt;
#endif
EOCC
        }
    }
    print $out_cc <<EOCC;
    s += std::to_string(flags);
    return s;
}

EOCC
}

close $to_cc;
close $to_h;
