LIB ?= ../target/release/libwispers_connect_client.dylib
CXX ?= cc

all: ffi_demo

ffi_demo: ffi_demo.c $(LIB)
	$(CXX) -I../include ffi_demo.c $(LIB) -o ffi_demo

clean:
	rm -f ffi_demo
