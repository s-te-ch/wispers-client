package wispersgo

/*
#include <stdlib.h>
#include "wispers_helpers.h"
*/
import "C"
import (
	"io"
	"math"
	"runtime"
	"time"
	"unsafe"
)

// QuicConnection wraps a WispersQuicConnectionHandle.
type QuicConnection struct {
	handle
}

// OpenStream opens a new bidirectional QUIC stream.
func (c *QuicConnection) OpenStream() (*QuicStream, error) {
	ptr := c.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicOpenStreamAsync(
		(*C.WispersQuicConnectionHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(c)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case unsafe.Pointer:
		return &QuicStream{handle: handle{ptr: v}}, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// AcceptStream waits for an incoming QUIC stream from the peer.
func (c *QuicConnection) AcceptStream() (*QuicStream, error) {
	ptr := c.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicAcceptStreamAsync(
		(*C.WispersQuicConnectionHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(c)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case unsafe.Pointer:
		return &QuicStream{handle: handle{ptr: v}}, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// Ping checks that the peer is still reachable. It sends a QUIC PING and waits
// for the peer's transport to acknowledge it.
//
// Returns ErrTimeout if no acknowledgement arrives within timeout,
// ErrConnectionFailed if the connection is closed or closing.
func (c *QuicConnection) Ping(timeout time.Duration) error {
	ptr := c.requireOpen()
	var timeoutMs uint32
	if timeout > 0 {
		timeoutMs = uint32(min(max(timeout.Milliseconds(), 1), math.MaxUint32))
	}
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicPingAsync(
		(*C.WispersQuicConnectionHandle)(ptr),
		C.uint32_t(timeoutMs),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return err
	}
	runtime.KeepAlive(c)
	if err, ok := call.wait().(error); ok {
		return err
	}
	return nil
}

// Close closes the QUIC connection asynchronously, waiting for completion.
// The handle is consumed.
func (c *QuicConnection) Close() error {
	ptr := c.consume()
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicCloseAsync(
		(*C.WispersQuicConnectionHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		// Still free the handle on error.
		C.wispers_quic_connection_free((*C.WispersQuicConnectionHandle)(ptr))
		return err
	}
	if err, ok := call.wait().(error); ok {
		return err
	}
	return nil
}

// CloseWithError closes the QUIC connection, with error code and reason. The
// handle is consumed.
//
// errorCode and reason are application-defined; the peer reads them with
// PeerCloseInfo. errorCode must be at most 2^62-1 (QUIC's limit); reason is
// truncated to 1024 bytes.
func (c *QuicConnection) CloseWithError(errorCode uint64, reason string) error {
	ptr := c.consume()
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicCloseWithErrorAsync(
		(*C.WispersQuicConnectionHandle)(ptr),
		C.uint64_t(errorCode),
		cReason,
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		// Still free the handle on error.
		C.wispers_quic_connection_free((*C.WispersQuicConnectionHandle)(ptr))
		return err
	}
	if err, ok := call.wait().(error); ok {
		return err
	}
	return nil
}

// QuicCloseInfo describes how the peer closed a QUIC connection.
type QuicCloseInfo struct {
	// ClosedByApp is true if the peer's application closed the connection,
	// false if its QUIC stack did; ErrorCode is then a QUIC transport error
	// code (RFC 9000 section 20.1).
	ClosedByApp bool
	ErrorCode   uint64
	Reason      string
}

// PeerCloseInfo returns how the peer closed the connection, or nil if it hasn't.
// It is set as soon as the peer's close arrives; stream operations then fail
// with ErrConnectionFailed.
func (c *QuicConnection) PeerCloseInfo() *QuicCloseInfo {
	ptr := c.requireOpen()
	info := C.wispers_quic_connection_peer_close_info((*C.WispersQuicConnectionHandle)(ptr))
	runtime.KeepAlive(c)
	if info == nil {
		return nil
	}
	defer C.wispers_quic_close_info_free(info)
	return &QuicCloseInfo{
		ClosedByApp: bool(C.wispers_quic_close_info_closed_by_app(info)),
		ErrorCode:   uint64(C.wispers_quic_close_info_error_code(info)),
		Reason:      C.GoString(C.wispers_quic_close_info_reason(info)),
	}
}

// QuicStream wraps a WispersQuicStreamHandle.
type QuicStream struct {
	handle
}

// Write writes data to the QUIC stream.
func (s *QuicStream) Write(data []byte) error {
	ptr := s.requireOpen()
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicStreamWriteAsync(
		(*C.WispersQuicStreamHandle)(ptr),
		dataPtr,
		C.size_t(len(data)),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return err
	}
	runtime.KeepAlive(data)
	runtime.KeepAlive(s)
	if err, ok := call.wait().(error); ok {
		return err
	}
	return nil
}

// Read reads up to maxLen bytes from the QUIC stream.
func (s *QuicStream) Read(maxLen int) ([]byte, error) {
	ptr := s.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicStreamReadAsync(
		(*C.WispersQuicStreamHandle)(ptr),
		C.size_t(maxLen),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(s)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case dataResult:
		if len(v.data) == 0 {
			return nil, io.EOF
		}
		return v.data, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// Finish sends FIN on the write side. The stream can still be read from.
func (s *QuicStream) Finish() error {
	ptr := s.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicStreamFinishAsync(
		(*C.WispersQuicStreamHandle)(ptr),
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

// Shutdown stops both sending and receiving on the stream.
func (s *QuicStream) Shutdown() error {
	ptr := s.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callQuicStreamShutdownAsync(
		(*C.WispersQuicStreamHandle)(ptr),
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

// Close frees the QUIC stream handle.
func (s *QuicStream) Close() {
	ptr := s.consume()
	C.wispers_quic_stream_free((*C.WispersQuicStreamHandle)(ptr))
}
