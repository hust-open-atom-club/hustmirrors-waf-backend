package echo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

func newBlockAdminServer(t *testing.T, token string) (*Server, *captureAudit) {
	t.Helper()
	cfg := &config.Config{}
	config.ApplyDefaults(cfg)
	cfg.Admin.Enabled = true
	cfg.Admin.Auth.Token = token
	cfg.Admin.MutationsEnabled = true
	cfg.Admin.IPBlock.Enabled = true
	cfg.Admin.IPBlock.DefaultTTL = time.Hour
	cfg.Admin.IPBlock.MaxTTL = 24 * time.Hour
	blocker := risk.NewIPPendingBlocker(4, time.Hour)
	t.Cleanup(func() { _ = blocker.Close() })
	svc, err := admin.New(admin.Options{Config: cfg, Pending: blocker, IPBlocks: blocker})
	require.NoError(t, err)
	server := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: svc})
	audit := &captureAudit{}
	server.auditLog = audit
	return server, audit
}

func TestAdminRiskBlocksAddAndUnblock(t *testing.T) {
	server, audit := newBlockAdminServer(t, "secret-token")

	body := `{"ip":"192.0.2.60","confirm_ip":"192.0.2.60","ttl_seconds":3600,"reason":"suspicious downloader"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/risk.blocks.add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	server.Echo().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "192.0.2.60")

	var response admin.StandardResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.True(t, response.OK)

	events := audit.all()
	require.Len(t, events, 1)
	assert.Equal(t, "risk.blocks.add", events[0].Action)
	assert.Equal(t, "token", events[0].Actor)
	assert.True(t, events[0].OK)
	assert.Len(t, events[0].Target, 12)
	assert.NotEqual(t, "192.0.2.60", events[0].Target)
	assert.Equal(t, "suspicious downloader", events[0].Reason)
	assert.Equal(t, int64(3600), events[0].TTLSeconds)

	unblockBody := `{"ip":"192.0.2.60","confirm_ip":"192.0.2.60"}`
	unblockReq := httptest.NewRequest(http.MethodPost, "/admin/api/risk.blocks.unblock", strings.NewReader(unblockBody))
	unblockReq.Header.Set("Content-Type", "application/json")
	unblockReq.Header.Set("Authorization", "Bearer secret-token")
	unblockRec := httptest.NewRecorder()
	server.Echo().ServeHTTP(unblockRec, unblockReq)
	require.Equal(t, http.StatusOK, unblockRec.Code, unblockRec.Body.String())
	assert.NotContains(t, unblockRec.Body.String(), "192.0.2.60")
}

func TestAdminRiskBlocksMutationPolicy(t *testing.T) {
	t.Run("none auth is read only", func(t *testing.T) {
		server, audit := newBlockAdminServer(t, "")
		body := `{"ip":"192.0.2.61","confirm_ip":"192.0.2.61","reason":"test"}`
		req := httptest.NewRequest(http.MethodPost, "/admin/api/risk.blocks.add", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.Echo().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "MUTATION_AUTH_REQUIRED")
		events := audit.all()
		require.Len(t, events, 1)
		assert.False(t, events[0].OK)
		assert.Equal(t, "MUTATION_AUTH_REQUIRED", events[0].Code)
		assert.NotContains(t, events[0].Detail, "192.0.2.61")
	})

	t.Run("missing token is audited", func(t *testing.T) {
		server, audit := newBlockAdminServer(t, "secret-token")
		req := httptest.NewRequest(http.MethodPost, "/admin/api/risk.blocks.list", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.Echo().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		events := audit.all()
		require.Len(t, events, 1)
		assert.Equal(t, "risk.blocks.list", events[0].Action)
		assert.Equal(t, "unknown", events[0].Actor)
		assert.Equal(t, "UNAUTHORIZED", events[0].Code)
		assert.False(t, events[0].OK)
	})

	t.Run("invalid reason is not copied to audit", func(t *testing.T) {
		server, audit := newBlockAdminServer(t, "secret-token")
		body := "{\"ip\":\"192.0.2.62\",\"confirm_ip\":\"192.0.2.62\",\"reason\":\"bad\\nreason\"}"
		req := httptest.NewRequest(http.MethodPost, "/admin/api/risk.blocks.add", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer secret-token")
		rec := httptest.NewRecorder()
		server.Echo().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		events := audit.all()
		require.Len(t, events, 1)
		assert.Empty(t, events[0].Reason)
		assert.Len(t, events[0].Target, 12)
		assert.NotContains(t, events[0].Detail, "192.0.2.62")
	})
}
