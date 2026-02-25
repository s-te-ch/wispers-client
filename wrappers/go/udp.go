package wispers

/*
#include "wispers_helpers.h"
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// UdpConnection wraps a WispersUdpConnectionHandle.
type UdpConnection struct {
	handle
}

// Send sends data over the UDP connection. This is synchronous and non-blocking.
func (c *UdpConnection) Send(data []byte) error {
	ptr := c.requireOpen()
	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	status := C.wispers_udp_connection_send(
		(*C.WispersUdpConnectionHandle)(ptr),
		dataPtr,
		C.size_t(len(data)),
	)
	runtime.KeepAlive(data)
	runtime.KeepAlive(c)
	return errorFromStatus(int(status))
}

// Recv receives data from the UDP connection. Blocks until data arrives.
func (c *UdpConnection) Recv() ([]byte, error) {
	ptr := c.requireOpen()
	call := newPendingCall()
	defer call.cancel()
	status := C.callUdpRecvAsync(
		(*C.WispersUdpConnectionHandle)(ptr),
		call.ctx(),
	)
	if err := errorFromStatus(int(status)); err != nil {
		return nil, err
	}
	runtime.KeepAlive(c)
	switch v := call.wait().(type) {
	case error:
		return nil, v
	case dataResult:
		return v.data, nil
	default:
		panic("wispers: unexpected bridge result type")
	}
}

// Close closes and frees the UDP connection handle.
func (c *UdpConnection) Close() {
	ptr := c.consume()
	C.wispers_udp_connection_close((*C.WispersUdpConnectionHandle)(ptr))
}
