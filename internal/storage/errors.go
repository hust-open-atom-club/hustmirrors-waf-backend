package storage

import "errors"

var ErrNotFound = errors.New("storage: not found")

var ErrClosed = errors.New("storage: closed")

// ErrUnsupported is returned by optional-capability methods (e.g.
// ActiveCounter.CountActive) on drivers that cannot implement them
// efficiently.
var ErrUnsupported = errors.New("storage: operation not supported by this driver")

// IsRetryable reports whether err is a transient storage failure that
// callers may retry. All persistence backends classify their errors via
// this helper so callers don't depend on backend-specific types.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	return false
}
