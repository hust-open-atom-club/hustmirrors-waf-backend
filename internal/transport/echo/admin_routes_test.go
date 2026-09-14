package echo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
)

func TestAdminRoutesExposePhase3ControlPlane(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Token = ""
	svc, err := admin.New(admin.Options{Config: cfg})
	require.NoError(t, err)
	server := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: svc})

	paths := make(map[string]bool)
	for _, route := range server.Echo().Routes() {
		paths[route.Path] = true
	}
	for _, path := range []string{
		"/admin/api/system.health",
		"/admin/api/dashboard.summary",
		"/admin/api/dashboard.series",
		"/admin/api/stats.summary",
		"/admin/api/stats.timeseries",
		"/admin/api/config.get",
		"/admin/api/config.validate",
		"/admin/api/config.status",
		"/admin/api/config.draft.save",
		"/admin/api/config.draft.get",
		"/admin/api/config.draft.discard",
		"/admin/api/config.diff",
		"/admin/api/config.apply",
		"/admin/api/config.history",
		"/admin/api/config.history.get",
		"/admin/api/config.rollback",
		"/admin/api/rule.list",
		"/admin/api/rule.preview",
		"/admin/api/token.get",
		"/admin/api/pending.list",
		"/admin/api/risk.blocks.list",
		"/admin/api/risk.blocks.add",
		"/admin/api/risk.blocks.unblock",
		"/admin/api/audit.list",
		"/admin/api/audit.search",
	} {
		assert.True(t, paths[path], path)
	}
	assert.False(t, paths["/admin/api/rule.reload"], "phase 3 uses config.apply instead of rule.reload")
}
