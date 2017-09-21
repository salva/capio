
H_FILES := capio.h

ifneq ($(WITH_PERL),)
	PERL_ARCHLIB := $(shell perl -MConfig -E 'say $$Config{archlib}')
	CPPFLAGS := $(CPPFLAGS) -DWITH_PERL -I"$(PERL_ARCHLIB)/CORE"
	LDFLAGS := $(LDFLAGS) -lperl
	H_FILES := $(H_FILES) perl.h
endif



all: capio capio.1

capio: capio.cpp $(H_FILES)
	g++ -std=gnu++11 $(CPPFLAGS) -O0 -g capio.cpp $(LDFLAGS) -o capio

capio.1: capio.pod
	pod2man -center "General Commands Manual" -section 1 capio.pod >capio.1

