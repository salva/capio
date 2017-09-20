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

* How does the underdocumented SCP protocol work?

      capio -f -mn -l0 -l1 -n "*/ssh" scp localhost:/etc/default/networking /tmp

  Output in "quote with new lines" format. Note how `capio` follows
  the `dups` syscalls and traces file descriptors 5 and 6 too, which
  are aliases for the selected 0 and 1:

      # 3418 dup(fd:0) = 5
      # 3418 dup(fd:1) = 6
      # 3418 read(fd:5) = 1
      < "\0"
      # 3418 write(fd:6) = 21
      > "C0644 306 networking\n"
      # 3418 read(fd:5) = 1
      < "\0"
      # 3418 write(fd:6) = 307
      > "# Configuration for networking init script being run during\n"
      > "# the boot sequence\n"
      > "\n"
      > "# Set to 'no' to skip interfaces configuration on boot\n"
      > "#CONFIGURE_INTERFACES=yes\n"
      > "\n"
      > "# Don't configure these interfaces. Shell wildcards supported/\n"
      > "#EXCLUDE_INTERFACES=\n"
      > "\n"
      > "# Set to 'yes' to enable additional verbosity\n"
      > "#VERBOSE=no\n"
      > "\0"
      # 3418 read(fd:5) = 1
      < "\0"
      # 3418 close(fd:6) = 0
      # 3418 close(fd:5) = 0

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
