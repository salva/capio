
all: capio capio.1

capio: capio.cpp
	g++ -O0 -g capio.cpp -o capio

capio.1: capio.pod
	pod2man -center "General Commands Manual" -section 1 capio.pod >capio.1

