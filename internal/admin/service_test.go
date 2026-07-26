package admin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

func TestService_Ping(t *testing.T) {
	svc, err := New(Options{})
	require.NoError(t, err)
	r, err := svc.Ping(context.Background(), PingRequest{})
	require.NoError(t, err)
	assert.True(t, r.OK)
}

func TestService_SystemInfo(t *testing.T) {
	svc, _ := New(Options{})
	r, err := svc.SystemInfo(context.Background(), SystemInfoRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, r.GoVersion)
}

func TestService_ConfigValidate_Valid(t *testing.T) {
	svc, _ := New(Options{})
	r, err := svc.ConfigValidate(context.Background(), ConfigValidateRequest{
		ConfigYAML: `
pow:
  modes:
    ip_bound:
      enabled: true
      min_difficulty: 22
      max_difficulty: 28
      max_ttl_seconds: 86400
    generic:
      enabled: true
      min_difficulty: 22
      max_difficulty: 28
      max_ttl_seconds: 1800
      max_uses: 5
`,
	})
	require.NoError(t, err)
	assert.True(t, r.OK, "problems: %v", r.Problems)
}

func TestService_ConfigValidate_Invalid(t *testing.T) {
	svc, _ := New(Options{})
	r, err := svc.ConfigValidate(context.Background(), ConfigValidateRequest{
		ConfigYAML: `
pow:
  modes:
    ip_bound:
      enabled: false
    generic:
      enabled: false
`,
	})
	require.NoError(t, err)
	assert.False(t, r.OK)
	assert.NotEmpty(t, r.Problems)
}

func TestService_RulePreview_NoEngine(t *testing.T) {
	svc, _ := New(Options{})
	r, err := svc.RulePreview(context.Background(), RulePreviewRequest{
		Request: RulePreviewRequestContext{Path: "/x.iso", IsProtected: true, PowStatus: "missing"},
	})
	require.NoError(t, err)
	assert.False(t, r.OK)
	assert.Contains(t, r.Error, "risk engine")
}

func TestService_RulePreview_WithEngine(t *testing.T) {
	chains := risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: "REJECT", Reason: "default_deny"},
		},
	}
	eng, err := risk.NewEngine(chains)
	require.NoError(t, err)
	svc, _ := New(Options{RiskEngine: eng})
	r, err := svc.RulePreview(context.Background(), RulePreviewRequest{
		Request: RulePreviewRequestContext{Path: "/x.iso", IsProtected: true, PowStatus: "missing"},
	})
	require.NoError(t, err)
	assert.True(t, r.OK)
	assert.Equal(t, "REJECT", r.Decision.Target)
	assert.Equal(t, "default_deny", r.Decision.Reason)
}

func TestService_RuleReload_NotImplemented(t *testing.T) {
	svc, _ := New(Options{})
	r, err := svc.RuleReload(context.Background(), RuleReloadRequest{})
	require.NoError(t, err)
	assert.False(t, r.OK)
	assert.Contains(t, r.Error, "not implemented")
}

func TestNopAuditLogger(t *testing.T) {
	NopAuditLogger{}.Log(context.Background(), AuditEvent{Action: "system.ping"})
}
