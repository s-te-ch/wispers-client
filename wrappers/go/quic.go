package wispers

/*
#include "wispers_helpers.h"
*/
import "C"
import (
	"runtime"
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
