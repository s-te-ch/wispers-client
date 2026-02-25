UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LIB_EXT := dylib
else
    LIB_EXT := so
endif

# Resolve to absolute paths so CGo can find headers from any working directory.
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
LIB_DIR ?= $(abspath $(ROOT)/../../target/debug)
INCLUDE ?= $(abspath $(ROOT)/../../wispers-connect/include)

export CGO_CFLAGS=-I$(INCLUDE)
export CGO_LDFLAGS=-L$(LIB_DIR) -lwispers_connect

.PHONY: build test clean

build:
	go build ./...

test:
	go test ./...

clean:
	go clean ./...
