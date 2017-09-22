
H_FILES := capio.h flags.h

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

capio: capio.o flags.o

flags.h: flags.pl flags.yaml
	perl ./flags.pl flags.yaml flags.cc flags.h

flags.cc: flags.pl flags.yaml
	perl ./flags.pl flags.yaml flags.cc flags.h

capio.1: capio.pod
	pod2man -center "General Commands Manual" -section 1 capio.pod >capio.1

