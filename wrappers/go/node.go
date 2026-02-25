package wispersgo

/*
#include "wispers_helpers.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// Node wraps a WispersNodeHandle and provides operations on a wispers node.
type Node struct {
	handle
}

// State returns the current state of the node.
func (n *Node) State() NodeState {
	ptr := n.requireOpen()
	s := C.wispers_node_state((*C.WispersNodeHandle)(ptr))
	return NodeState(s)
}

// Register registers the node with the hub using a registration token.
// Requires Pending state.
func (n *Node) Register(token string) error {
	ptr := n.requireOpen()
	cToken := C.CString(token)
	defer C.free(unsafe.Pointer(cToken))
	call := newPendingCall()
	defer call.cancel()
	status := C.callRegisterAsync(
		(*C.WispersNodeHandle)(ptr),
		cToken,
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return err
	}
	runtime.KeepAlive(n)
	if err, ok := call.wait().(error); ok {
		return err
	}
	return nil
}

// Activate activates the node using a pairing code ("node_number-secret").
// Requires Registered state.
func (n *Node) Activate(pairingCode string) error {
	ptr := n.requireOpen()
	cCode := C.CString(pairingCode)
	defer C.free(unsafe.Pointer(cCode))
	call := newPendingCall()
	defer call.cancel()
	status := C.callActivateAsync(
		(*C.WispersNodeHandle)(ptr),
		cCode,
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return err
	}
	runtime.KeepAlive(n)
	if err, ok := call.wait().(error); ok {
		return err
	}
	return nil
}

// Logout deregisters the node and deletes local state. The Node handle is
// consumed and must not be used afterward.
func (n *Node) Logout() error {
	ptr := n.consume()
	call := newPendingCall()
	defer call.cancel()
	status := C.callLogoutAsync(
		(*C.WispersNodeHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return err
	}
	if err, ok := call.wait().(error); ok {
		return err
	}
	return nil
}

// ListNodes lists all nodes in the connectivity group.
// Requires Registered or Activated state.
func (n *Node) ListNodes() ([]NodeInfo, error) {
	ptr := n.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callListNodesAsync(
		(*C.WispersNodeHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(n)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case []NodeInfo:
		return v, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// StartServing starts a serving session. Returns a ServingSession whose
// Incoming field is nil for registered (non-activated) nodes.
// Requires Registered or Activated state.
func (n *Node) StartServing() (*ServingSession, error) {
	ptr := n.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callStartServingAsync(
		(*C.WispersNodeHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(n)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case startServingResult:
		ss := &ServingSession{
			serving: handle{ptr: v.servingPtr},
			session: handle{ptr: v.sessionPtr},
		}
		if v.incomingPtr != nil {
			ss.Incoming = &IncomingConnections{handle: handle{ptr: v.incomingPtr}}
		}
		return ss, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// ConnectUdp connects to a peer node using UDP transport.
// Requires Activated state.
func (n *Node) ConnectUdp(peerNodeNumber int32) (*UdpConnection, error) {
	ptr := n.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callConnectUdpAsync(
		(*C.WispersNodeHandle)(ptr),
		C.int32_t(peerNodeNumber),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(n)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case unsafe.Pointer:
		return &UdpConnection{handle: handle{ptr: v}}, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// ConnectQuic connects to a peer node using QUIC transport.
// Requires Activated state.
func (n *Node) ConnectQuic(peerNodeNumber int32) (*QuicConnection, error) {
	ptr := n.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callConnectQuicAsync(
		(*C.WispersNodeHandle)(ptr),
		C.int32_t(peerNodeNumber),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(n)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case unsafe.Pointer:
		return &QuicConnection{handle: handle{ptr: v}}, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// Close frees the node handle.
func (n *Node) Close() {
	ptr := n.consume()
	C.wispers_node_free((*C.WispersNodeHandle)(ptr))
}
