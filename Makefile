all: aes.c sbox.h
	clang aes.c -Wall -o aes

clean: aes
	rm aes
