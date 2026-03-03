package wispersgo

import "fmt"

// Status represents a WispersStatus code from the C library.
type Status int

const (
	StatusSuccess            Status = 0
	StatusNullPointer        Status = 1
	StatusInvalidUTF8        Status = 2
	StatusStoreError         Status = 3
	StatusAlreadyRegistered  Status = 4
	StatusNotRegistered      Status = 5
	StatusUnexpectedStage    Status = 6 // Deprecated
	StatusNotFound           Status = 7
	StatusBufferTooSmall     Status = 8
	StatusMissingCallback    Status = 9
	StatusInvalidPairingCode Status = 10
	StatusActivationFailed   Status = 11
	StatusHubError           Status = 12
	StatusConnectionFailed   Status = 13
	StatusTimeout            Status = 14
	StatusInvalidState       Status = 15
	StatusUnauthenticated    Status = 16
	StatusPeerRejected       Status = 17
	StatusPeerUnavailable    Status = 18
)

// Error wraps a non-success WispersStatus code with optional detail.
type Error struct {
	Status Status
	Detail string // human-readable detail from the Rust library (may be empty)
}

func (e *Error) Error() string {
	var base string
	switch e.Status {
	case StatusNullPointer:
		base = "wispers: null pointer"
	case StatusInvalidUTF8:
		base = "wispers: invalid UTF-8"
	case StatusStoreError:
		base = "wispers: store error"
	case StatusAlreadyRegistered:
		base = "wispers: already registered"
	case StatusNotRegistered:
		base = "wispers: not registered"
	case StatusNotFound:
		base = "wispers: not found"
	case StatusBufferTooSmall:
		base = "wispers: buffer too small"
	case StatusMissingCallback:
		base = "wispers: missing callback"
	case StatusInvalidPairingCode:
		base = "wispers: invalid pairing code"
	case StatusActivationFailed:
		base = "wispers: activation failed"
	case StatusHubError:
		base = "wispers: hub error"
	case StatusConnectionFailed:
		base = "wispers: connection failed"
	case StatusTimeout:
		base = "wispers: timeout"
	case StatusInvalidState:
		base = "wispers: invalid state"
	case StatusUnauthenticated:
		base = "wispers: unauthenticated (node removed)"
	case StatusPeerRejected:
		base = "wispers: peer rejected request"
	case StatusPeerUnavailable:
		base = "wispers: peer unavailable"
	default:
		base = fmt.Sprintf("wispers: unknown status %d", e.Status)
	}
	if e.Detail != "" {
		return base + ": " + e.Detail
	}
	return base
}

// Sentinel errors for use with errors.Is().
var (
	ErrNullPointer        = &Error{Status: StatusNullPointer}
	ErrInvalidUTF8        = &Error{Status: StatusInvalidUTF8}
	ErrStoreError         = &Error{Status: StatusStoreError}
	ErrAlreadyRegistered  = &Error{Status: StatusAlreadyRegistered}
	ErrNotRegistered      = &Error{Status: StatusNotRegistered}
	ErrNotFound           = &Error{Status: StatusNotFound}
	ErrBufferTooSmall     = &Error{Status: StatusBufferTooSmall}
	ErrMissingCallback    = &Error{Status: StatusMissingCallback}
	ErrInvalidPairingCode = &Error{Status: StatusInvalidPairingCode}
	ErrActivationFailed   = &Error{Status: StatusActivationFailed}
	ErrHubError           = &Error{Status: StatusHubError}
	ErrConnectionFailed   = &Error{Status: StatusConnectionFailed}
	ErrTimeout            = &Error{Status: StatusTimeout}
	ErrInvalidState       = &Error{Status: StatusInvalidState}
	ErrUnauthenticated    = &Error{Status: StatusUnauthenticated}
	ErrPeerRejected       = &Error{Status: StatusPeerRejected}
	ErrPeerUnavailable    = &Error{Status: StatusPeerUnavailable}
)

// Is implements errors.Is support so callers can match sentinel values.
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.Status == t.Status
	}
	return false
}

// errorFromStatus returns nil for success, or an *Error for any other status.
func errorFromStatus(status int) error {
	if status == 0 {
		return nil
	}
	return &Error{Status: Status(status)}
}
