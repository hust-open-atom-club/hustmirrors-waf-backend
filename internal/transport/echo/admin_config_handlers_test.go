package echo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/configstore"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
)

const adminConfigSecretCanary = "phase3-http-secret-canary"

func TestAdminConfigManagementHTTPFlowAndAudit(t *testing.T) {
	initial := adminConfigYAML(adminConfigSecretCanary, "info")
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(initial), 0o600))
	state, err := configstore.New(path, []byte(initial), true)
	require.NoError(t, err)

	cfg := &config.Config{}
	config.ApplyDefaults(cfg)
	cfg.Admin.Enabled = true
	cfg.Admin.Auth.Token = "t"
	cfg.Admin.Auth.Token = "admin-test-token"
	cfg.Admin.MutationsEnabled = true
	cfg.Admin.ConfigManagement.Enabled = true
	svc, err := admin.New(admin.Options{Config: cfg, ConfigState: state})
	require.NoError(t, err)
	server := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: svc})
	audit := &captureAudit{}
	server.auditLog = audit

	candidate := adminConfigYAML("${SECRET:KEEP}", "debug")
	saveBody := map[string]interface{}{"base_revision": 1, "config_yaml": candidate}
	save := doAdminConfigRPC(t, server, "config.draft.save", saveBody)
	require.Equal(t, http.StatusOK, save.Code, save.Body.String())
	assert.NotContains(t, save.Body.String(), adminConfigSecretCanary)
	var saveEnvelope struct {
		Data admin.ConfigDraftResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(save.Body.Bytes(), &saveEnvelope))
	draft := saveEnvelope.Data
	require.NotEmpty(t, draft.DraftID)

	validate := doAdminConfigRPC(t, server, "config.validate", map[string]interface{}{"draft_id": draft.DraftID, "draft_revision": draft.DraftRevision})
	require.Equal(t, http.StatusOK, validate.Code, validate.Body.String())

	diffRec := doAdminConfigRPC(t, server, "config.diff", map[string]interface{}{"draft_id": draft.DraftID, "draft_revision": draft.DraftRevision})
	require.Equal(t, http.StatusOK, diffRec.Code, diffRec.Body.String())
	assert.NotContains(t, diffRec.Body.String(), adminConfigSecretCanary)
	var diffEnvelope struct {
		Data admin.ConfigDiffResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(diffRec.Body.Bytes(), &diffEnvelope))
	diff := diffEnvelope.Data
	require.NotEmpty(t, diff.PreviewID)

	applyRec := doAdminConfigRPC(t, server, "config.apply", map[string]interface{}{
		"draft_id": draft.DraftID, "draft_revision": draft.DraftRevision,
		"preview_id": diff.PreviewID, "expected_revision": diff.BaseRevision,
		"reason": "routine configuration update", "acknowledged": true,
		"confirmation_phrase": diff.ConfirmationPhrase,
	})
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.NotContains(t, applyRec.Body.String(), adminConfigSecretCanary)

	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(onDisk), adminConfigSecretCanary)
	assert.Contains(t, string(onDisk), "level: debug")

	events := audit.all()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	assert.Equal(t, "config.apply", last.Action)
	assert.Equal(t, "token", last.Actor)
	assert.True(t, last.OK)
	assert.Equal(t, uint64(2), last.Revision)
	assert.Positive(t, last.ChangeCount)
	assert.True(t, last.RestartRequired)
	assert.Equal(t, "routine configuration update", last.Reason)
	for _, event := range events {
		encoded, marshalErr := json.Marshal(event)
		require.NoError(t, marshalErr)
		assert.NotContains(t, string(encoded), adminConfigSecretCanary)
	}
}

func TestAdminConfigManagementNoneAuthIsReadOnly(t *testing.T) {
	cfg := &config.Config{}
	config.ApplyDefaults(cfg)
	cfg.Admin.Enabled = true
	cfg.Admin.Auth.Token = ""
	cfg.Admin.MutationsEnabled = true
	cfg.Admin.ConfigManagement.Enabled = true
	store, err := configstore.New("", nil, false)
	require.NoError(t, err)
	svc, err := admin.New(admin.Options{Config: cfg, ConfigState: store})
	require.NoError(t, err)
	server := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: svc})

	rec := doAdminConfigRPCWithoutAuth(t, server, "config.draft.save", map[string]interface{}{"base_revision": 1, "config_yaml": "pow: {}"})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "MUTATION_AUTH_REQUIRED")
}

func doAdminConfigRPC(t *testing.T, server *Server, action string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	rec := doAdminConfigRPCWithoutAuth(t, server, action, body)
	return rec
}

func doAdminConfigRPCWithoutAuth(t *testing.T, server *Server, action string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/"+action, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	if server.cfg != nil && server.cfg.Admin.Auth.Token != "" {
		req.Header.Set("Authorization", "Bearer admin-test-token")
	}
	rec := httptest.NewRecorder()
	server.Echo().ServeHTTP(rec, req)
	return rec
}

func adminConfigYAML(secret, level string) string {
	return fmt.Sprintf(`server:
  listen: 127.0.0.1:8080
pow:
  enabled: true
  public_salt: %q
  modes:
    ip_bound:
      enabled: true
    generic:
      enabled: false
storage:
  driver: memory
  counter_driver: memory
risk_control:
  enabled: false
admin:
  enabled: true
  listen: 127.0.0.1:8081
  auth:
    token: %q
  mutations_enabled: true
  config_management:
    enabled: true
logging:
  level: %s
  format: json
`, secret, secret, level)
}
