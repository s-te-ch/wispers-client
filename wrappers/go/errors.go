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
)

// Error wraps a non-success WispersStatus code.
type Error struct {
	Status Status
}

func (e *Error) Error() string {
	switch e.Status {
	case StatusNullPointer:
		return "wispers: null pointer"
	case StatusInvalidUTF8:
		return "wispers: invalid UTF-8"
	case StatusStoreError:
		return "wispers: store error"
	case StatusAlreadyRegistered:
		return "wispers: already registered"
	case StatusNotRegistered:
		return "wispers: not registered"
	case StatusNotFound:
		return "wispers: not found"
	case StatusBufferTooSmall:
		return "wispers: buffer too small"
	case StatusMissingCallback:
		return "wispers: missing callback"
	case StatusInvalidPairingCode:
		return "wispers: invalid pairing code"
	case StatusActivationFailed:
		return "wispers: activation failed"
	case StatusHubError:
		return "wispers: hub error"
	case StatusConnectionFailed:
		return "wispers: connection failed"
	case StatusTimeout:
		return "wispers: timeout"
	case StatusInvalidState:
		return "wispers: invalid state"
	default:
		return fmt.Sprintf("wispers: unknown status %d", e.Status)
	}
}

// Sentinel errors for use with errors.Is().
var (
	ErrNullPointer        = &Error{StatusNullPointer}
	ErrInvalidUTF8        = &Error{StatusInvalidUTF8}
	ErrStoreError         = &Error{StatusStoreError}
	ErrAlreadyRegistered  = &Error{StatusAlreadyRegistered}
	ErrNotRegistered      = &Error{StatusNotRegistered}
	ErrNotFound           = &Error{StatusNotFound}
	ErrBufferTooSmall     = &Error{StatusBufferTooSmall}
	ErrMissingCallback    = &Error{StatusMissingCallback}
	ErrInvalidPairingCode = &Error{StatusInvalidPairingCode}
	ErrActivationFailed   = &Error{StatusActivationFailed}
	ErrHubError           = &Error{StatusHubError}
	ErrConnectionFailed   = &Error{StatusConnectionFailed}
	ErrTimeout            = &Error{StatusTimeout}
	ErrInvalidState       = &Error{StatusInvalidState}
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
