# capio

For most hackers, **strace** is the primary go-to tool when they need to
see what some program is doing under the hood, but inspecting **strace**
output can be a laborious and time consuming task.

**capio** is very similar to **strace** but it focus on inspecting the
I/O of the traced programs.

## Installation

Currently, **capio** works only on Linux for x86_64.

Clone the GitHub repository at https://github.com/salva/capio.git and
run `make`.

If you want to compile capio with Perl support (highly recommended),
run `make` as follows:

    make WITH_PERL=1

## Running

See the man page: https://github.com/salva/capio/blob/master/capio.pod

## Examples

* How does the underdocumented SCP protocol works?

      capio -f -l5 -l6 -n "*/ssh" scp localhost:/etc/passwd /tmp/passwd

* Monitoring `tea4cups` IPP requests:

  The `examples` directory contains the script `ipp.pl` that can be used to
  unpack IPP requests as follows:

      sudo ./capio -f -n "/*/python*" -p `pidof cupsd` \
           -N 'socket:*' -M examples/ipp.pl

## Bugs and support

**capio** is a still a very young program, expect lots of bugs and yet
missing features. Also, the command line options names and their handling is
still not stable and may change.

Don't hesitate to Report any bugs you may find, missing features, etc.
