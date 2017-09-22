#/usr/bin/perl

use strict;
use warnings;

use YAML ();
use feature qw(:all);
use Data::Dumper;

our $debug = 1;

my $from = shift // 'flags.yaml';
my $to = shift // $from =~ s/(:?\.yaml)?$/.cc/r;

my $data = YAML::LoadFile($from) or die "invalid data in YAML file $from";

$debug and warn Dumper($data) ."\n";

open my $out, '>', $to or die "$to: $!";

for my $header (@{$data->{headers}}) {
    print $out <<EOC;
#include <$header>
EOC
}

print $out <<EOC;
#include <string>
using namespace std;
EOC

my $groups = $data->{groups};
for my $name (sort keys %$groups) {
    print $out <<EOC;
static string
${name}_flags2string(long long flags) {
    string s("");
EOC
    for my $flag (@{$groups->{$name}}) {
        print $out <<EOC;
    if ($flag == 0) {
        if (flags == 0)
            s += "$flag|";
    }
    else {
        if ((flags & $flag) == $flag)
            s += "$flag|";
    }
EOC
    }
    print $out <<EOC;
    s += to_string(flags);
    return s;
}

EOC
}
