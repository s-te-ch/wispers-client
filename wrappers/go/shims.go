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
	// `gi` is an opaque WispersGroupInfo handle. Walk it via accessors and
	// copy all data into Go values before freeing.
	cGI := (*C.WispersGroupInfo)(gi)
	id := C.GoString(C.wispers_group_info_id(cGI))
	var name *string
	if cName := C.wispers_group_info_name(cGI); cName != nil {
		n := C.GoString(cName)
		name = &n
	}
	createdAtMillis := int64(C.wispers_group_info_created_at_millis(cGI))
	state := GroupState(C.wispers_group_info_state(cGI))
	count := int(C.wispers_group_info_nodes_count(cGI))
	nodes := make([]NodeInfo, count)
	for i := 0; i < count; i++ {
		n := C.wispers_group_info_node_at(cGI, C.size_t(i))
		nodes[i] = NodeInfo{
			NodeNumber:       int32(C.wispers_node_number(n)),
			Name:             C.GoString(C.wispers_node_name(n)),
			Metadata:         C.GoString(C.wispers_node_metadata(n)),
			IsSelf:           bool(C.wispers_node_is_self(n)),
			State:            NodeState(C.wispers_group_node_state(n)),
			LastSeenAtMillis: int64(C.wispers_node_last_seen_at_millis(n)),
			IsOnline:         bool(C.wispers_node_is_online(n)),
		}
	}
	C.wispers_group_info_free(cGI)
	resolvePendingCall(ctx, groupInfoResult{
		id:              id,
		name:            name,
		createdAtMillis: createdAtMillis,
		state:           state,
		nodes:           nodes,
	})
}

//export goWispersServingStatusCallback
func goWispersServingStatusCallback(ctx unsafe.Pointer, status C.int, detail *C.char, ss unsafe.Pointer) {
	if int(status) != 0 {
		resolvePendingCall(ctx, &Error{Status: Status(status), Detail: C.GoString(detail)})
		return
	}
	// `ss` is an opaque WispersServingStatus handle. Copy all data into Go
	// values via accessors before freeing.
	cSS := (*C.WispersServingStatus)(ss)
	count := int(C.wispers_serving_status_nodes_awaiting_cosign_count(cSS))
	awaiting := make([]int32, count)
	for i := 0; i < count; i++ {
		awaiting[i] = int32(C.wispers_serving_status_node_awaiting_cosign_at(cSS, C.size_t(i)))
	}
	result := ServingStatus{
		Connected:           bool(C.wispers_serving_status_connected(cSS)),
		NodeNumber:          int32(C.wispers_serving_status_node_number(cSS)),
		ConnectivityGroupID: C.GoString(C.wispers_serving_status_connectivity_group_id(cSS)),
		CodesOutstanding:    int(C.wispers_serving_status_codes_outstanding(cSS)),
		NodesAwaitingCosign: awaiting,
	}
	C.wispers_serving_status_free(cSS)
	resolvePendingCall(ctx, result)
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
