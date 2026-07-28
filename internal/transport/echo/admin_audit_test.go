package echo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
)

// captureAudit records events instead of logging them.
type captureAudit struct {
	mu     sync.Mutex
	events []admin.AuditEvent
}

func (c *captureAudit) Log(_ context.Context, e admin.AuditEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureAudit) all() []admin.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]admin.AuditEvent(nil), c.events...)
}

func newAuditServer(t *testing.T, cfg *config.Config) (*Server, *captureAudit) {
	t.Helper()
	asvc, err := admin.New(admin.Options{Config: cfg})
	require.NoError(t, err)
	s := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})
	cap := &captureAudit{}
	s.auditLog = cap
	return s, cap
}

// TestAdminAudit_RecordsSuccess covers the happy path. The audit chain was
// previously inert: Service held an AuditLogger it never called, and the
// only implementation discarded everything.
func TestAdminAudit_RecordsSuccess(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "none"
	s, cap := newAuditServer(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/system.ping", nil)
	req.Header.Set("X-Real-IP", "10.1.2.3")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	events := cap.all()
	require.Len(t, events, 1)
	assert.Equal(t, "system.ping", events[0].Action)
	assert.True(t, events[0].OK)
	assert.Equal(t, "10.1.2.3", events[0].IP)
	assert.Equal(t, "anonymous", events[0].Actor)
}

// TestAdminAudit_RecordsBindFailure pins that a malformed request is
// audited too. Binding fails in the transport layer and never reaches the
// service, so auditing there would have missed it entirely.
func TestAdminAudit_RecordsBindFailure(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "none"
	s, cap := newAuditServer(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/config.validate",
		strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	events := cap.all()
	require.Len(t, events, 1)
	assert.Equal(t, "config.validate", events[0].Action)
	assert.False(t, events[0].OK, "a rejected request must be recorded as a failure")
}

// TestAdminAudit_ActorFromBasicAuth checks the identity carried into the
// trail, and that token auth reports a placeholder rather than echoing any
// part of the credential.
func TestAdminAudit_ActorFromBasicAuth(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "basic"
	cfg.Admin.Auth.Username = "ops"
	cfg.Admin.Auth.Password = "pw"
	s, cap := newAuditServer(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/system.ping", nil)
	req.SetBasicAuth("ops", "pw")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	events := cap.all()
	require.Len(t, events, 1)
	assert.Equal(t, "ops", events[0].Actor)

	cfgToken := &config.Config{}
	cfgToken.Admin.Auth.Type = "token"
	cfgToken.Admin.Auth.Token = "secret-token-value"
	s2, cap2 := newAuditServer(t, cfgToken)

	req2 := httptest.NewRequest(http.MethodPost, "/admin/api/system.ping", nil)
	req2.Header.Set("Authorization", "Bearer secret-token-value")
	rec2 := httptest.NewRecorder()
	s2.Echo().ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)

	events2 := cap2.all()
	require.Len(t, events2, 1)
	assert.Equal(t, "token", events2[0].Actor)
	assert.NotContains(t, events2[0].Actor, "secret-token-value",
		"the credential must never reach the audit trail")
}

// TestAdminAudit_HonoursConfigSwitch: admin.audit_log had no readers, so
// auditing could not be turned off. Absent still means on.
func TestAdminAudit_HonoursConfigSwitch(t *testing.T) {
	newServer := func(auditLog *bool) *Server {
		cfg := &config.Config{}
		cfg.Admin.Auth.Type = "none"
		cfg.Admin.AuditLog = auditLog
		asvc, err := admin.New(admin.Options{Config: cfg})
		require.NoError(t, err)
		return NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})
	}

	off, on := false, true
	assert.IsType(t, admin.NopAuditLogger{}, newServer(&off).auditLog,
		"audit_log: false must disable recording")
	assert.IsType(t, &admin.LogAuditLogger{}, newServer(&on).auditLog)
	assert.IsType(t, &admin.LogAuditLogger{}, newServer(nil).auditLog,
		"an omitted audit_log must not silently disable auditing")
}
