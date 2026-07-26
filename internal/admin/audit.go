package admin

import (
	"context"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
)

// AuditLogger records admin actions.
//
// The admin API can inspect config and evaluate rules, so who called what
// is worth keeping. Records go to the structured log rather than a table:
// the log is already shipped and retained, and an append-only stream is a
// better fit for audit than rows nothing ever reads.
type AuditLogger interface {
	Log(ctx context.Context, e AuditEvent)
}

// AuditEvent is one admin action.
type AuditEvent struct {
	Action    string // RPC name, e.g. "config.validate"
	Actor     string // authenticated identity, or "anonymous"
	RequestID string
	IP        string
	OK        bool   // whether the action succeeded
	Detail    string // short context; must not carry secrets
}

// NopAuditLogger discards everything. Used in tests and when no logger is
// wired.
type NopAuditLogger struct{}

func (NopAuditLogger) Log(context.Context, AuditEvent) {}

// LogAuditLogger writes audit events to the application log at info level,
// tagged event=admin_audit so they can be filtered out for retention.
type LogAuditLogger struct {
	logger logging.Logger
}

func NewLogAuditLogger(l logging.Logger) AuditLogger {
	if l == nil {
		return NopAuditLogger{}
	}
	return &LogAuditLogger{logger: l}
}

func (a *LogAuditLogger) Log(ctx context.Context, e AuditEvent) {
	fields := []logging.Field{
		logging.String("event", "admin_audit"),
		logging.String("action", e.Action),
		logging.String("actor", e.Actor),
		logging.Bool("ok", e.OK),
	}
	if e.RequestID != "" {
		fields = append(fields, logging.String("request_id", e.RequestID))
	}
	if e.IP != "" {
		fields = append(fields, logging.String("ip", e.IP))
	}
	if e.Detail != "" {
		fields = append(fields, logging.String("detail", e.Detail))
	}
	a.logger.Info(ctx, "admin action", fields...)
}

var (
	_ AuditLogger = NopAuditLogger{}
	_ AuditLogger = (*LogAuditLogger)(nil)
)
