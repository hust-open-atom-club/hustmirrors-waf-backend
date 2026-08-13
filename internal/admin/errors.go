package admin

import (
	"errors"
	"net/http"
)

// RPCError is a safe, client-facing Admin API error. Message must not include
// credentials, raw target IPs, request bodies, or backend error details.
type RPCError struct {
	Status  int
	Code    string
	Message string
}

func (e *RPCError) Error() string { return e.Message }

func newRPCError(status int, code, message string) error {
	return &RPCError{Status: status, Code: code, Message: message}
}

func ValidationError(message string) error {
	return newRPCError(http.StatusBadRequest, "VALIDATION_FAILED", message)
}

func MutationsDisabledError() error {
	return newRPCError(http.StatusForbidden, "MUTATIONS_DISABLED", "admin mutations are disabled")
}

func MutationAuthRequiredError() error {
	return newRPCError(http.StatusForbidden, "MUTATION_AUTH_REQUIRED", "admin mutations require token or basic authentication")
}

func IPBlockDisabledError() error {
	return newRPCError(http.StatusForbidden, "IP_BLOCK_DISABLED", "admin IP block operations are disabled")
}

func BlockStoreUnavailableError() error {
	return newRPCError(http.StatusServiceUnavailable, "BLOCK_STORE_UNAVAILABLE", "IP block controller is unavailable")
}

func AsRPCError(err error) (*RPCError, bool) {
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		return rpcErr, true
	}
	return nil, false
}
