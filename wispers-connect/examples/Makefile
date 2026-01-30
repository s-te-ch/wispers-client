# FFI Examples Makefile
#
# Targets:
#   make           - Build all
#   make test      - Build and run integration tests
#   make demo      - Build demo program
#   make clean     - Remove built files

# Detect platform and set library extension
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LIB_EXT := dylib
else
    LIB_EXT := so
endif

# Use debug build by default, override with: make LIB=../../target/release/libwispers_connect.$(LIB_EXT)
LIB ?= ../../target/debug/libwispers_connect.$(LIB_EXT)
INCLUDE ?= ../include
CC ?= cc
CFLAGS ?= -Wall -Wextra -pedantic

.PHONY: all test demo clean

all: ffi_test ffi_demo

# Integration tests - verifies ABI compatibility
ffi_test: ffi_test.c $(LIB) $(INCLUDE)/wispers_connect.h
	$(CC) $(CFLAGS) -I$(INCLUDE) ffi_test.c $(LIB) -o ffi_test

test: ffi_test
	./ffi_test

# Demo program - shows real-world usage (like wconnect but via FFI)
ffi_demo: ffi_demo.c $(LIB) $(INCLUDE)/wispers_connect.h
	$(CC) $(CFLAGS) -I$(INCLUDE) ffi_demo.c $(LIB) -o ffi_demo

demo: ffi_demo
	@echo "Demo built. Run with: ./ffi_demo [--hub <addr>] <command>"
	@echo "Commands: status, register <token>, activate <code>, serve [--pairing-code], ping <node>"

clean:
	rm -f ffi_test ffi_demo
