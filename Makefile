# CLEFIA cipher library - Makefile
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -Iinclude
AR      ?= ar
PREFIX  ?= /usr/local

LIB     = libclefia.a
SHLIB   = libclefia.so

.PHONY: all lib shared static cli test clean install

all: static shared cli test

static: $(LIB)
shared: $(SHLIB)

src/clefia.o: src/clefia.c include/clefia.h
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): src/clefia.o
	$(AR) rcs $@ $^

$(SHLIB): src/clefia.c include/clefia.h
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

test: tests/test_clefia
	./tests/test_clefia

tests/test_clefia: tests/test_clefia.c $(LIB) include/clefia.h
	$(CC) $(CFLAGS) -Iinclude $< $(LIB) -o $@

cli: clefia-cli
clefia-cli: tools/clefia-cli.c $(LIB) include/clefia.h
	$(CC) $(CFLAGS) -Iinclude $< $(LIB) -o $@

clean:
	rm -f src/clefia.o $(LIB) $(SHLIB) tests/test_clefia clefia-cli

install: static shared
	install -d $(PREFIX)/lib $(PREFIX)/include
	install -m 644 $(LIB) $(SHLIB) $(PREFIX)/lib/
	install -m 644 include/clefia.h $(PREFIX)/include/
