CC = gcc
DEBUG = -g
CFLAGS = -Wall -Wextra -Wshadow -Wunreachable-code \
         -Wredundant-decls -Wmissing-declarations \
         -Wold-style-definition -Wmissing-prototypes \
         -Wdeclaration-after-statement -Wno-return-local-addr \
         -Wunsafe-loop-optimizations -Wuninitialized -Werror \
         -Wno-unused-parameter
LDFLAGS = -pthread -lcrypt

all: thread_hash

thread_hash: thread_hash.o
	$(CC) $(DEBUG) $(CFLAGS) -o thread_hash thread_hash.o $(LDFLAGS)

thread_hash.o: thread_hash.c thread_hash.h
	$(CC) $(DEBUG) $(CFLAGS) -c thread_hash.c

clean:
	rm -f *.o thread_hash *~

tar:
	tar cvfa thread_hash_${LOGNAME}.tar.gz thread_hash.c thread_hash.h Makefile

