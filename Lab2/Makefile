# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls \
         -Wmissing-declarations -Wold-style-definition \
         -Wmissing-prototypes -Wdeclaration-after-statement \
         -Wno-return-local-addr -Wunsafe-loop-optimizations -Wuninitialized -Werror

# Targets
all: caesar xor

caesar: caesar.o
	$(CC) $(CFLAGS) -o caesar caesar.o

caesar.o: caesar.c
	$(CC) $(CFLAGS) -c caesar.c

xor: xor.o
	$(CC) $(CFLAGS) -o xor xor.o

xor.o: xor.c
	$(CC) $(CFLAGS) -c xor.c

clean:
	rm -f *.o caesar xor 
tar: clean
	tar -czvf Muhumed-Lab2.tar.gz caesar.c xor.c Makefile