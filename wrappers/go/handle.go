package wispersgo

import (
	"sync/atomic"
	"unsafe"
)

// handle is a base type for opaque C handles. It tracks whether the handle has
// been closed/consumed, preventing use-after-free.
type handle struct {
	ptr    unsafe.Pointer
	closed atomic.Bool
}

// requireOpen returns the raw pointer, panicking if the handle has been closed.
func (h *handle) requireOpen() unsafe.Pointer {
	if h.closed.Load() {
		panic("wispers: use of closed handle")
	}
	return h.ptr
}

// consume returns the raw pointer and marks the handle as closed. This is used
// for C calls that take ownership of the handle. Panics if already closed.
func (h *handle) consume() unsafe.Pointer {
	if !h.closed.CompareAndSwap(false, true) {
		panic("wispers: use of closed handle")
	}
	return h.ptr
}
