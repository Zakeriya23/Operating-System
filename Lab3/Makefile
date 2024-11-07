CC = gcc
DEBUG = -g
CFLAGS = -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls -Wmissing-declarations -Wold-style-definition \
		  -Wmissing-prototypes -Wdeclaration-after-statement -Wno-return-local-addr -Wunsafe-loop-optimizations \
		  -Wuninitialized -Werror
		  
all: viktar 

viktar: viktar.o
	$(CC) $(DEBUG) $(CFLAGS) -o viktar viktar.o -lz -lssl -lcrypto

viktar.o: viktar.c viktar.h
	$(CC) $(DEBUG) $(CFLAGS) -c viktar.c

clean:
	rm -f *.o viktar *~ \#*
	
tar:
	tar cvfa viktar_${LOGNAME}.tar.gz viktar.c Makefile