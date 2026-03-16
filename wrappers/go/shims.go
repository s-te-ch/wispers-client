package wispersgo

// This file contains //export functions callable from C. Per CGo rules, files
// with //export directives may only include declarations (not definitions) in
// the C preamble.

/*
#include "wispers_connect.h"
*/
import "C"
import (
	"runtime/cgo"
	"unsafe"
)

//export goWispersCallback
func goWispersCallback(ctx unsafe.Pointer, status C.int, detail *C.char) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	resolvePendingCall(ctx, error(nil))
}

//export goWispersInitCallback
func goWispersInitCallback(ctx unsafe.Pointer, status C.int, detail *C.char, nodeHandle unsafe.Pointer, state C.int) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	resolvePendingCall(ctx, initResult{nodePtr: nodeHandle, state: NodeState(state)})
}

//export goWispersGroupInfoCallback
func goWispersGroupInfoCallback(ctx unsafe.Pointer, status C.int, detail *C.char, gi unsafe.Pointer) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	// Copy data out of the C struct before resolving.
	cGI := (*C.WispersGroupInfo)(gi)
	state := GroupState(cGI.state)
	count := int(cGI.nodes_count)
	nodes := make([]NodeInfo, count)
	if count > 0 {
		cNodes := unsafe.Slice((*C.WispersNode)(unsafe.Pointer(cGI.nodes)), count)
		for i := 0; i < count; i++ {
			nodes[i] = NodeInfo{
				NodeNumber:       int32(cNodes[i].node_number),
				Name:             C.GoString(cNodes[i].name),
				Metadata:         C.GoString(cNodes[i].metadata),
				IsSelf:           bool(cNodes[i].is_self),
				ActivationStatus: ActivationStatus(cNodes[i].activation_status),
				LastSeenAtMillis: int64(cNodes[i].last_seen_at_millis),
				IsOnline:         bool(cNodes[i].is_online),
			}
		}
	}
	C.wispers_group_info_free((*C.WispersGroupInfo)(gi))
	resolvePendingCall(ctx, groupInfoResult{state: state, nodes: nodes})
}

//export goWispersStartServingCallback
func goWispersStartServingCallback(ctx unsafe.Pointer, status C.int, detail *C.char, serving unsafe.Pointer, session unsafe.Pointer, incoming unsafe.Pointer) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	resolvePendingCall(ctx, startServingResult{
		servingPtr:  serving,
		sessionPtr:  session,
		incomingPtr: incoming,
	})
}

//export goWispersActivationCodeCallback
func goWispersActivationCodeCallback(ctx unsafe.Pointer, status C.int, detail *C.char, code *C.char) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	goCode := C.GoString(code)
	C.wispers_string_free(code)
	resolvePendingCall(ctx, goCode)
}

//export goWispersUdpConnectionCallback
func goWispersUdpConnectionCallback(ctx unsafe.Pointer, status C.int, detail *C.char, conn unsafe.Pointer) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	resolvePendingCall(ctx, conn)
}

//export goWispersDataCallback
func goWispersDataCallback(ctx unsafe.Pointer, status C.int, detail *C.char, data *C.uint8_t, length C.size_t) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	// Copy data out of the C buffer (only valid during callback).
	n := int(length)
	buf := make([]byte, n)
	if n > 0 {
		src := unsafe.Slice((*byte)(unsafe.Pointer(data)), n)
		copy(buf, src)
	}
	resolvePendingCall(ctx, dataResult{data: buf})
}

//export goWispersQuicConnectionCallback
func goWispersQuicConnectionCallback(ctx unsafe.Pointer, status C.int, detail *C.char, conn unsafe.Pointer) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	resolvePendingCall(ctx, conn)
}

//export goWispersQuicStreamCallback
func goWispersQuicStreamCallback(ctx unsafe.Pointer, status C.int, detail *C.char, stream unsafe.Pointer) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	resolvePendingCall(ctx, stream)
}

// --- Storage callback shims ---
// These use cgo.Handle to recover the StorageCallbacks interface.

//export goStorageLoadRootKey
func goStorageLoadRootKey(ctx unsafe.Pointer, outKey *C.uint8_t, outKeyLen C.size_t) C.int {
	cb := cgo.Handle(uintptr(ctx)).Value().(StorageCallbacks)
	data, err := cb.LoadRootKey()
	if err != nil {
		return C.int(StatusStoreError)
	}
	if data == nil {
		return C.int(StatusNotFound)
	}
	if len(data) > int(outKeyLen) {
		return C.int(StatusBufferTooSmall)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(outKey)), int(outKeyLen))
	copy(dst, data)
	return C.int(StatusSuccess)
}

//export goStorageSaveRootKey
func goStorageSaveRootKey(ctx unsafe.Pointer, key *C.uint8_t, keyLen C.size_t) C.int {
	cb := cgo.Handle(uintptr(ctx)).Value().(StorageCallbacks)
	data := C.GoBytes(unsafe.Pointer(key), C.int(keyLen))
	if err := cb.SaveRootKey(data); err != nil {
		return C.int(StatusStoreError)
	}
	return C.int(StatusSuccess)
}

//export goStorageDeleteRootKey
func goStorageDeleteRootKey(ctx unsafe.Pointer) C.int {
	cb := cgo.Handle(uintptr(ctx)).Value().(StorageCallbacks)
	if err := cb.DeleteRootKey(); err != nil {
		return C.int(StatusStoreError)
	}
	return C.int(StatusSuccess)
}

//export goStorageLoadRegistration
func goStorageLoadRegistration(ctx unsafe.Pointer, buffer *C.uint8_t, bufferLen C.size_t, outLen *C.size_t) C.int {
	cb := cgo.Handle(uintptr(ctx)).Value().(StorageCallbacks)
	data, err := cb.LoadRegistration()
	if err != nil {
		return C.int(StatusStoreError)
	}
	if data == nil {
		return C.int(StatusNotFound)
	}
	if len(data) > int(bufferLen) {
		*outLen = C.size_t(len(data))
		return C.int(StatusBufferTooSmall)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(bufferLen))
	copy(dst, data)
	*outLen = C.size_t(len(data))
	return C.int(StatusSuccess)
}

//export goStorageSaveRegistration
func goStorageSaveRegistration(ctx unsafe.Pointer, buffer *C.uint8_t, bufferLen C.size_t) C.int {
	cb := cgo.Handle(uintptr(ctx)).Value().(StorageCallbacks)
	data := C.GoBytes(unsafe.Pointer(buffer), C.int(bufferLen))
	if err := cb.SaveRegistration(data); err != nil {
		return C.int(StatusStoreError)
	}
	return C.int(StatusSuccess)
}

//export goStorageDeleteRegistration
func goStorageDeleteRegistration(ctx unsafe.Pointer) C.int {
	cb := cgo.Handle(uintptr(ctx)).Value().(StorageCallbacks)
	if err := cb.DeleteRegistration(); err != nil {
		return C.int(StatusStoreError)
	}
	return C.int(StatusSuccess)
}
