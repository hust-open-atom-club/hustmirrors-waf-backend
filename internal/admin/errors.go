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
	return newRPCError(http.StatusForbidden, "MUTATION_AUTH_REQUIRED", "admin mutations require token authentication")
}

func IPBlockDisabledError() error {
	return newRPCError(http.StatusForbidden, "IP_BLOCK_DISABLED", "admin IP block operations are disabled")
}

func BlockStoreUnavailableError() error {
	return newRPCError(http.StatusServiceUnavailable, "BLOCK_STORE_UNAVAILABLE", "IP block controller is unavailable")
}

func ConfigWritesDisabledError() error {
	return newRPCError(http.StatusForbidden, "CONFIG_WRITES_DISABLED", "configuration writes are disabled")
}
func ConfigSourceUnmanagedError() error {
	return newRPCError(http.StatusForbidden, "CONFIG_SOURCE_UNMANAGED", "configuration source is not managed")
}
func DraftNotFoundError() error {
	return newRPCError(http.StatusNotFound, "DRAFT_NOT_FOUND", "configuration draft was not found")
}
func DraftExpiredError() error {
	return newRPCError(http.StatusGone, "DRAFT_EXPIRED", "configuration draft expired")
}
func DraftConflictError() error {
	return newRPCError(http.StatusConflict, "DRAFT_VERSION_CONFLICT", "configuration draft changed; reload it")
}
func ConfigConflictError() error {
	return newRPCError(http.StatusConflict, "CONFIG_VERSION_CONFLICT", "configuration changed; reload current state")
}
func ValidationRequiredError() error {
	return newRPCError(http.StatusConflict, "VALIDATION_REQUIRED", "validate the current draft before diff or apply")
}
func DiffRequiredError() error {
	return newRPCError(http.StatusConflict, "DIFF_REQUIRED", "generate a new configuration diff before apply")
}
func PreviewStaleError() error {
	return newRPCError(http.StatusConflict, "PREVIEW_STALE", "configuration diff is stale; generate it again")
}
func HistoryNotFoundError() error {
	return newRPCError(http.StatusNotFound, "HISTORY_NOT_FOUND", "configuration history entry was not found")
}
func ConfigInvalidError() error {
	return newRPCError(http.StatusUnprocessableEntity, "CONFIG_INVALID", "candidate configuration is invalid")
}
func SecretPlaceholderError() error {
	return newRPCError(http.StatusBadRequest, "SECRET_PLACEHOLDER_INVALID", "invalid secret placeholder")
}
func ConfirmationRequiredError() error {
	return newRPCError(http.StatusPreconditionRequired, "CONFIRMATION_REQUIRED", "confirmation is required")
}
func ConfirmationInvalidError() error {
	return newRPCError(http.StatusPreconditionRequired, "CONFIRMATION_INVALID", "confirmation phrase is invalid")
}
func ConfigPersistError() error {
	return newRPCError(http.StatusInternalServerError, "CONFIG_PERSIST_FAILED", "configuration could not be persisted")
}
func ConfigTooLargeError() error {
	return newRPCError(http.StatusRequestEntityTooLarge, "CONFIG_TOO_LARGE", "configuration candidate is too large")
}
func PreviewExpiredError() error {
	return newRPCError(http.StatusGone, "PREVIEW_EXPIRED", "configuration diff preview expired")
}

func AsRPCError(err error) (*RPCError, bool) {
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		return rpcErr, true
	}
	return nil, false
}
