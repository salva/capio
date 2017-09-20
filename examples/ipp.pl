use 5.024;
#use strict;
use warnings;
use feature 'refaliasing';
no warnings 'experimental::refaliasing';
use Data::Dumper;
our ($PID, $FD, $R, $W, $DIR, $EXE, $FN, $LEN);

use Net::IPP::IPP;
use Net::IPP::IPPRequest;

BEGIN {
    # workaround for some bug I don't plan to investigate on Net::IPP::IPPRequest :-(
    for (qw(DEBUG VERSION STATUS REQUEST_ID GROUPS TYPE)) {
        no strict;
        *{"Net::IPP::IPPRequest::$_"} = \*{"Net::IPP::IPP::$_"};
        *{"Net::IPP::IPPAttribute::$_"} = \*{"Net::IPP::IPP::$_"}
    }
}

$Data::Dumper::Useqq = 1;
$; = "-";

my %handler;
my %buffer;
my %type;
my %len;

sub start {
    my $id = shift;
    my $next_handler;
    if ($buffer{$id} =~ /^POST\s/) {
        $next_handler = \&post;
    }
    elsif ($buffer{$id} =~ /^HTTP\/1/) {
        $next_handler = \&response;
    }
    else {
        $buffer{$id} = '';
        return;
    }
    $handler{$id} = $next_handler;
    $next_handler->($id);
}

sub post {
    my $id = shift;
    $buffer{$id} =~ s{
                         ^(
                             (POST|HEAD) \s+ (\S+) \s+ HTTP/1\.\S+ \r?\n
                             (
                                 (\s* ([^\s:]+) \s* : \s* .*? \s* \r?\n) *
                             )
                         )
                         \r?\n
                 }{}x or return;

    my ($head, $method, $url, $headers) = ($1, $2, $3, $4);
    print "HTTP request: method: $method, url: $url, headers:...\n$headers\n";

    my $next_handler;
    if ($headers =~ /^Content-Length:\s*(\d+)/m) {
        $len{$id} = $1;
        if ($headers =~ /^Content-Type:\s*(\S+)/m) {
            $type{$id} = $1;
        }
        $next_handler = \&body_len;
    }
    else {
        return start($id)
    }
    $next_handler->($id);
}

sub body_len {
    my $id = shift;
    my $len = $len{$id};
    if (length $buffer{$id} >= $len) {
        my $body = substr $buffer{$id}, 0, $len, '';
        my $type = delete $type{$id};
        if ($type eq 'application/ipp') {
            ipp($id, $body);
        }
        delete $handler{$id};
        start($id);
    }
    # wait for more data to arrive
}

sub ipp {
    my ($id, $load) = @_;

    my %hash;
    Net::IPP::IPPRequest::bytesToHash($load, \%hash);
    say "ipp load for $id: ", Dumper(\%hash);
}

sub response {
    my $id = shift;
}

sub _ {
    next unless defined;
    my $id = join('-', $PID, $FD, $DIR);
    $buffer{$id} .= $_;
    my $handler = $handler{$id} //= \&start;
    $handler->($id);
}
