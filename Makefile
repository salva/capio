
H_FILES := capio.h flags.h sockaddr.h syscall.h regs.h dual_ostream.h memory.h

ifneq ($(WITH_PERL),)
	PERL_ARCHLIB := $(shell perl -MConfig -E 'say $$Config{archlib}')
	CPPFLAGS += -DWITH_PERL -I"$(PERL_ARCHLIB)/CORE"
	LDLIBS += -lperl
	H_FILES += perl.h
endif

CXXFLAGS += -std=gnu++11 -g -O0
CC := g++

all: capio capio.1

#capio: capio.cpp $(H_FILES)
#	g++ -std=gnu++11 $(CPPFLAGS) -O0 -g capio.cpp $(LDFLAGS) -o capio

capio: capio.o flags.o sockaddr.o util.o syscall.o dumper.o dual_ostream.o memory.o

flags.h: helpers/flags.pl flags.yaml
	perl ./helpers/flags.pl flags.yaml flags.cc flags.h

flags.cc: helpers/flags.pl flags.yaml
	perl ./helpers/flags.pl flags.yaml flags.cc flags.h

syscall.h: helpers/syscall.pl docs/syscall_64.tbl
	perl ./helpers/syscall.pl docs/syscall_64.tbl syscall.cc syscall.h

syscall.cc: helpers/syscall.pl docs/syscall_64.tbl
	perl ./helpers/syscall.pl docs/syscall_64.tbl syscall.cc syscall.h

capio.1: capio.pod
	pod2man -center "General Commands Manual" -section 1 capio.pod >capio.1

*.cc: $(H_FILES)
