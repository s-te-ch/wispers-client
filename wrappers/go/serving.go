package wispersgo

/*
#include "wispers_helpers.h"
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// ServingSession wraps a serving handle, session, and optional incoming
// connections. For registered (non-activated) nodes, Incoming is nil.
type ServingSession struct {
	serving  handle // WispersServingHandle
	session  handle // WispersServingSession
	Incoming *IncomingConnections
}

// GeneratePairingCode generates a pairing code for endorsing a new node.
func (s *ServingSession) GeneratePairingCode() (string, error) {
	ptr := s.serving.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callGeneratePairingCodeAsync(
		(*C.WispersServingHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return "", err
	}
	runtime.KeepAlive(s)
	switch v := call.wait().(type) {
	case error:
		return "", v
	case string:
		return v, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// Run runs the serving session event loop. Blocks until the session ends.
// The session handle is consumed by this call.
func (s *ServingSession) Run() error {
	ptr := s.session.consume()
	call := newPendingCall()
	defer call.cancel()
	status := C.callServingSessionRunAsync(
		(*C.WispersServingSession)(ptr),
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

// Shutdown requests the serving session to shut down.
func (s *ServingSession) Shutdown() error {
	ptr := s.serving.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callServingShutdownAsync(
		(*C.WispersServingHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return err
	}
	runtime.KeepAlive(s)
	if err, ok := call.wait().(error); ok {
		return err
	}
	return nil
}

// Close frees all handles owned by this serving session.
func (s *ServingSession) Close() {
	if s.Incoming != nil {
		s.Incoming.Close()
		s.Incoming = nil
	}
	if !s.session.closed.Load() {
		ptr := s.session.consume()
		C.wispers_serving_session_free((*C.WispersServingSession)(ptr))
	}
	ptr := s.serving.consume()
	C.wispers_serving_handle_free((*C.WispersServingHandle)(ptr))
}

// IncomingConnections wraps a WispersIncomingConnections handle for accepting
// incoming P2P connections.
type IncomingConnections struct {
	handle
}

// AcceptUdp waits for an incoming UDP connection from a peer.
func (ic *IncomingConnections) AcceptUdp() (*UdpConnection, error) {
	ptr := ic.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callIncomingAcceptUdpAsync(
		(*C.WispersIncomingConnections)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(ic)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case unsafe.Pointer:
		return &UdpConnection{handle: handle{ptr: v}}, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// AcceptQuic waits for an incoming QUIC connection from a peer.
func (ic *IncomingConnections) AcceptQuic() (*QuicConnection, error) {
	ptr := ic.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callIncomingAcceptQuicAsync(
		(*C.WispersIncomingConnections)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(ic)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case unsafe.Pointer:
		return &QuicConnection{handle: handle{ptr: v}}, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// Close frees the incoming connections handle.
func (ic *IncomingConnections) Close() {
	ptr := ic.consume()
	C.wispers_incoming_connections_free((*C.WispersIncomingConnections)(ptr))
}
