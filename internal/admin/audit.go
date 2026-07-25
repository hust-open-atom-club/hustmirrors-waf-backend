package admin

import "context"

// AuditLogger records admin actions for compliance.
type AuditLogger interface {
	Log(ctx context.Context, action, actor, requestID, summary string, details interface{}) error
}

type NopAuditLogger struct{}

func (NopAuditLogger) Log(_ context.Context, _, _, _, _ string, _ interface{}) error {
	return nil
}

type AuditEntry struct {
	ID        int64
	Action    string
	Actor     string
	RequestID string
	Summary   string
	Details   interface{}
	CreatedAt int64
}
