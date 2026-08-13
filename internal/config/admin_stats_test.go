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

func TestValidate_AdminStatsRejectsNonPositiveTimeout(t *testing.T) {
	cfg := validAdminStatsConfig()
	cfg.Admin.Stats.QueryTimeout = -time.Second
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query_timeout must be > 0")
}
