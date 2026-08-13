package echo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
)

func TestAdminRoutesExposeReadOnlyControlPlane(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "none"
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
		"/admin/api/config.get",
		"/admin/api/config.validate",
		"/admin/api/rule.list",
		"/admin/api/rule.preview",
		"/admin/api/token.get",
		"/admin/api/pending.list",
		"/admin/api/audit.list",
	} {
		assert.True(t, paths[path], path)
	}
	assert.False(t, paths["/admin/api/rule.reload"], "phase 1 must not expose mutating reload")
}
