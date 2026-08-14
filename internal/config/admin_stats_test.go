package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validAdminStatsConfig() *Config {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Pow.Modes.IPBound.Enabled = true
	cfg.Admin.Enabled = true
	cfg.Admin.Auth.Type = "none"
	return cfg
}

func TestValidate_AdminStatsRejectsNonHTTPURL(t *testing.T) {
	cfg := validAdminStatsConfig()
	cfg.Admin.Stats.PrometheusURL = "file:///private/metrics"
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute http or https URL")
}

func TestValidate_AdminStatsRequiresFixedLokiQuery(t *testing.T) {
	cfg := validAdminStatsConfig()
	cfg.Admin.Stats.LokiURL = "http://127.0.0.1:3100"
	cfg.Admin.Stats.LokiQuery = ""
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loki_query must be set")
}

func TestValidate_AdminIPBlockTTLRange(t *testing.T) {
	cfg := validAdminStatsConfig()
	cfg.Admin.IPBlock.DefaultTTL = 2 * time.Hour
	cfg.Admin.IPBlock.MaxTTL = time.Hour
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default_ttl must be <=")
}

func TestValidate_AdminConfigManagementRequiresMutationAuth(t *testing.T) {
	tests := []struct {
		name      string
		authType  string
		mutations bool
		want      string
	}{
		{name: "mutations disabled", authType: "token", mutations: false, want: "requires admin.mutations_enabled=true"},
		{name: "none auth", authType: "none", mutations: true, want: "requires admin.auth.type=token or basic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validAdminStatsConfig()
			cfg.Admin.Auth.Type = tt.authType
			cfg.Admin.MutationsEnabled = tt.mutations
			cfg.Admin.ConfigManagement.Enabled = true
			err := Validate(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestValidate_AdminStatsRejectsNonPositiveTimeout(t *testing.T) {
	cfg := validAdminStatsConfig()
	cfg.Admin.Stats.QueryTimeout = -time.Second
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query_timeout must be > 0")
}
