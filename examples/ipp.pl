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
# $| = 1;

my %handler;
my %buffer;
my %type;
my %len;

sub start {
    my $id = shift;
    if ($buffer{$id} =~ /^POST\s/) {
        $handler{$id} = \&post;
    }
    elsif ($buffer{$id} =~ /^HTTP\/1/) {
        $handler{$id} = \&response;
    }
    else {
        delete $handler{$id};
        $buffer{$id} = '';
        return;
    }
    $handler{$id}->($id);
}

sub find_header {
    my ($key, $headers) = @_;
    if ($headers =~ /^\Q$key\E\s*:\s*(\S+?)\s*$/m) {
        return $1;
    }
    undef
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

    if (defined ($len{$id} = find_header 'Content-Length', $headers)) {
        $type{$id} = find_header 'Content-Type', $headers;
        $handler{$id} = \&body_len;
    }
    else {
        return start($id)
    }
    $handler{$id}->($id);
}

sub body_len {
    warn "waiting for body...\n";
    my $id = shift;
    my $len = $len{$id};
    if (length $buffer{$id} >= $len) {
        my $body = substr $buffer{$id}, 0, $len, '';
        my $type = delete $type{$id};
        if ($type eq 'application/ipp') {
            ipp($id, $body);
        }
        start($id);
    }
    # wait for more data to arrive
}

sub ipp {
    my ($id, $load) = @_;

    warn "ipp packet...\n";
    my %hash;
    Net::IPP::IPPRequest::bytesToHash($load, \%hash);
    say "ipp load for $id: ", Dumper(\%hash);
}

sub response {
    warn "waiting for response...\n";
    my $id = shift;
    $buffer{$id} =~ s{
                         ^(
                             HTTP/\S+ \s+ (\d+) \s+ (\S+?) \s* \r?\n
                             (
                                 (\s* ([^\s:]+) \s* : \s* .*? \s* \r?\n) *
                             )
                         )
                         \r?\n
                 }{}x or return;
    my ($head, $code, $msg, $headers) = ($1, $2, $3, $4);

    print "HTTP response: code: $code, msg: $msg, headers:...\n$headers\n";

    if (defined ($len{$id} = find_header 'Content-Length', $headers)) {
        $type{$id} = find_header 'Content-Type', $headers;
        $handler{$id} = \&body_len;
    }
    else {
        return start($id)
    }
    $handler{$id}->($id);
}

sub _ {
    next unless defined;
    $| = 0;
    my $id = join('-', $PID, $FD, $DIR);
    $buffer{$id} .= $_;
    ($handler{$id} // \&start)->($id);
}
