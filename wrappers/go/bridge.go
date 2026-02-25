package wispersgo

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// pendingCall represents an in-flight async C call. It holds the void*ctx to
// pass to C functions and a channel that receives the result when the C
// callback fires.
//
// Typical usage:
//
//	call := newPendingCall()
//	defer call.cancel()
//	status := C.callSomethingAsync(handle, call.ctx())
//	if err := errorFromStatus(int(status)); err != nil {
//	    return err
//	}
//	return call.wait()
type pendingCall struct {
	id uint64
	ch chan any
}

// callbackBridge maps uint64 IDs to channels, allowing C async callbacks to
// deliver results back to waiting Go callers.
var callbackBridge struct {
	nextID  atomic.Uint64
	pending sync.Map // uint64 → chan any
}

// newPendingCall allocates a callback slot. The caller must either call wait()
// (which cleans up on completion) or cancel() (which cleans up without waiting).
// Using defer call.cancel() is safe even after wait() returns.
func newPendingCall() *pendingCall {
	id := callbackBridge.nextID.Add(1)
	ch := make(chan any, 1)
	callbackBridge.pending.Store(id, ch)
	return &pendingCall{id: id, ch: ch}
}

// ctx returns the void*ctx pointer to pass to C async functions.
func (p *pendingCall) ctx() unsafe.Pointer {
	return unsafe.Pointer(uintptr(p.id))
}

// cancel removes the pending slot without waiting. Safe to call multiple times
// or after wait() has already returned.
func (p *pendingCall) cancel() {
	callbackBridge.pending.Delete(p.id)
}

// wait blocks until the C callback fires and returns the result. The pending
// slot is cleaned up by the callback (bridgeResolve), so cancel() after wait()
// is a harmless no-op.
func (p *pendingCall) wait() any {
	return <-p.ch
}

// resolvePendingCall delivers a result to the pendingCall associated with the
// given void*ctx. Called from //export shim functions.
func resolvePendingCall(ctx unsafe.Pointer, val any) {
	id := uint64(uintptr(ctx))
	if v, ok := callbackBridge.pending.LoadAndDelete(id); ok {
		v.(chan any) <- val
	}
}
