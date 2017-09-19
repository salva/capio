
CFLAGS=-DCAPIO_PERL

all: capio capio.1

capio: capio.cpp
	g++ -O0 -g capio.cpp $(CFLAGS) -I"/usr/lib/x86_64-linux-gnu/perl/5.24/CORE" -o capio -lperl

capio.1: capio.pod
	pod2man -center "General Commands Manual" -section 1 capio.pod >capio.1

