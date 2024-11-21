CC = gcc
DEBUG = -g
CFLAGS = -Wall -Wshadow -Wunreachable-code -Wredundant-decls \
         -Wmissing-declarations -Wold-style-definition \
         -Wmissing-prototypes -Wdeclaration-after-statement \
         -Wno-return-local-addr -Wuninitialized -Wextra -Wunused
all: psush 

psush: psush.o cmd_parse.o
	$(CC) $(DEBUG) $(CFLAGS) -o psush psush.o cmd_parse.o

psush.o: psush.c 
	$(CC) $(DEBUG) $(CFLAGS) -c psush.c

cmd_parse.o: cmd_parse.c cmd_parse.h
	$(CC) $(DEBUG) $(CFLAGS) -c cmd_parse.c
clean:
	rm -f *.o psush *~
tar:
	tar cvfa psush_${LOGNAME}.tar.gz psush.c cmd_parse.c Makefile
