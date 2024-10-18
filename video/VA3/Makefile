CC = gcc
DEBUG = -g
DEFINES =
CFLAGS = $(DEBUG) -Wall -Wshadow -Wunreachable-code -Wredundant-decls \
			-Wmissing-declarations -Wold-style-definition -Wmissing-prototypes \
			-Wdeclaration-after-statement -Wextra $(DEFINES)

PROG1 = bin_write
PROG2 = bin_cat
PROG3 = bin_update
PROG4 = bin_add
PROGS = $(PROG1) $(PROG2) $(PROG3) $(PROG4)
INCLUDES = bin_file.h

all: $(PROGS)

$(PROG1): $(PROG1).o
	$(CC) $(CFLAGS) -o $@ $^

$(PROG1).o: $(PROG1).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<

$(PROG2): $(PROG2).o
	$(CC) $(CFLAGS) -o $@ $^

$(PROG2).o: $(PROG2).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<

$(PROG3): $(PROG3).o
	$(CC) $(CFLAGS) -o $@ $^

$(PROG3).o: $(PROG3).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<

$(PROG4): $(PROG4).o
	$(CC) $(CFLAGS) -o $@ $^

$(PROG4).o: $(PROG4).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<


clean cls:
	rm -f $(PROGS) *.o *~ \#*

tar:
	tar cvfa bin_files_${LOGNAME}.tar.gz *.[ch] [mM]akefile