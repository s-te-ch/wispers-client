package wispersgo

/*
#include "wispers_helpers.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"runtime/cgo"
	"unsafe"
)

// StorageCallbacks is the interface that host-provided storage must implement.
// Return (nil, nil) from Load methods to indicate "not found".
type StorageCallbacks interface {
	LoadRootKey() ([]byte, error)
	SaveRootKey(key []byte) error
	DeleteRootKey() error
	LoadRegistration() ([]byte, error)
	SaveRegistration(data []byte) error
	DeleteRegistration() error
}

// Storage wraps a WispersNodeStorageHandle.
type Storage struct {
	handle
	cgoHandle *cgo.Handle // non-nil for callback-backed storage; prevents GC
}

// NewInMemoryStorage creates a storage backed by in-memory state (for testing).
func NewInMemoryStorage() *Storage {
	ptr := C.wispers_storage_new_in_memory()
	return &Storage{handle: handle{ptr: unsafe.Pointer(ptr)}}
}

// NewStorage creates a storage backed by host-provided callbacks.
func NewStorage(cb StorageCallbacks) *Storage {
	h := cgo.NewHandle(cb)
	cCallbacks := C.makeStorageCallbacks(unsafe.Pointer(uintptr(h)))
	ptr := C.wispers_storage_new_with_callbacks(&cCallbacks)
	return &Storage{
		handle:    handle{ptr: unsafe.Pointer(ptr)},
		cgoHandle: &h,
	}
}

// ReadRegistration reads the local registration data (sync, no hub contact).
// Returns ErrNotFound if the node is not registered.
func (s *Storage) ReadRegistration() (*RegistrationInfo, error) {
	ptr := s.requireOpen()
	var cInfo C.WispersRegistrationInfo
	status := C.wispers_storage_read_registration(
		(*C.WispersNodeStorageHandle)(ptr),
		&cInfo,
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	info := &RegistrationInfo{
		ConnectivityGroupID: C.GoString(cInfo.connectivity_group_id),
		NodeNumber:          int32(cInfo.node_number),
		AuthToken:           C.GoString(cInfo.auth_token),
	}
	C.wispers_registration_info_free(&cInfo)
	return info, nil
}

// OverrideHubAddr overrides the hub address (for testing/staging).
func (s *Storage) OverrideHubAddr(addr string) error {
	ptr := s.requireOpen()
	cAddr := C.CString(addr)
	defer C.free(unsafe.Pointer(cAddr))
	status := C.wispers_storage_override_hub_addr(
		(*C.WispersNodeStorageHandle)(ptr),
		cAddr,
	)
	return errorFromStatus(int(status))
}

// RestoreOrInit restores or initializes the node state. Returns a Node and its
// current state. The Storage remains valid after this call.
func (s *Storage) RestoreOrInit() (*Node, NodeState, error) {
	ptr := s.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callRestoreOrInitAsync(
		(*C.WispersNodeStorageHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, 0, err
	}
	runtime.KeepAlive(s)
	switch v := call.wait().(type) {
	case error:
		return nil, 0, v
	case initResult:
		node := &Node{handle: handle{ptr: v.nodePtr}}
		return node, v.state, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// Close frees the storage handle.
func (s *Storage) Close() {
	ptr := s.consume()
	C.wispers_storage_free((*C.WispersNodeStorageHandle)(ptr))
	if s.cgoHandle != nil {
		s.cgoHandle.Delete()
		s.cgoHandle = nil
	}
}
