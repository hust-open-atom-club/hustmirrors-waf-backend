package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

type stubUsageReader struct {
	record *storage.UsageRecord
	err    error
}

func (s stubUsageReader) Get(context.Context, string) (*storage.UsageRecord, error) {
	return s.record, s.err
}

func TestService_ConfigGetRedactsSecrets(t *testing.T) {
	cfg := &config.Config{}
	config.ApplyDefaults(cfg)
	cfg.Pow.PublicSalt = "pow-secret"
	cfg.Pow.AllowedPreviousSalts = []string{"old-secret"}
	cfg.Storage.Postgres.DSN = "postgres://secret-user:secret-pass@db/private"
	cfg.Storage.Redis.Password = "redis-secret"
	cfg.Admin.Auth.Token = "admin-token-secret"
	cfg.Admin.Auth.TokenFile = "C:/secret/admin.token"
	cfg.Admin.Auth.Password = "admin-password-secret"
	cfg.Logging.LogSalt = "logging-secret"

	svc, err := New(Options{Config: cfg})
	require.NoError(t, err)
	result, err := svc.ConfigGet(context.Background(), ConfigGetRequest{})
	require.NoError(t, err)

	body, err := json.Marshal(result)
	require.NoError(t, err)
	encoded := string(body)
	for _, secret := range []string{
		"pow-secret", "old-secret", "secret-user", "secret-pass", "private",
		"redis-secret", "admin-token-secret", "C:/secret/admin.token",
		"admin-password-secret", "logging-secret",
	} {
		assert.NotContains(t, encoded, secret)
	}
	assert.Contains(t, encoded, "[redacted]")
}

func TestService_TokenGetReturnsMinimalRecord(t *testing.T) {
	record := &storage.UsageRecord{
		ID: "sign-id", Mode: "generic", Path: "/image.iso",
		Sign: "raw-sign-secret", TokenHash: "token-hash-secret",
		Uses: 2, MaxUses: 5, FirstIP: "192.0.2.1", LastIP: "192.0.2.2",
		UserAgent: "private-user-agent", ExpiresAt: 200, CreatedAt: 100, UpdatedAt: 150,
	}
	svc, err := New(Options{Usage: stubUsageReader{record: record}})
	require.NoError(t, err)

	result, err := svc.TokenGet(context.Background(), TokenGetRequest{SignID: record.ID})
	require.NoError(t, err)
	require.True(t, result.Found)
	assert.Equal(t, "sign-id", result.Token.ID)
	assert.Len(t, result.Token.IPHint, 12)

	body, err := json.Marshal(result)
	require.NoError(t, err)
	encoded := string(body)
	assert.NotContains(t, encoded, "raw-sign-secret")
	assert.NotContains(t, encoded, "token-hash-secret")
	assert.NotContains(t, encoded, "private-user-agent")
	assert.NotContains(t, encoded, "192.0.2.1")
	assert.NotContains(t, encoded, "192.0.2.2")
}

func TestService_TokenGetNotFound(t *testing.T) {
	svc, err := New(Options{Usage: stubUsageReader{err: storage.ErrNotFound}})
	require.NoError(t, err)
	result, err := svc.TokenGet(context.Background(), TokenGetRequest{SignID: "missing"})
	require.NoError(t, err)
	assert.False(t, result.Found)
}

func TestService_DashboardSeriesUsesMetricWhitelist(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[{"values":[[1000,"1.5"]]}]}}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	config.ApplyDefaults(cfg)
	cfg.Admin.Stats.PrometheusURL = server.URL
	svc, err := New(Options{Config: cfg})
	require.NoError(t, err)

	result, err := svc.DashboardSeries(context.Background(), DashboardSeriesRequest{
		Metric: "pow_denied_total", From: 900, To: 1100, Step: 15,
	})
	require.NoError(t, err)
	assert.True(t, result.Available)
	assert.Equal(t, metricQueries["pow_denied_total"], gotQuery)
	require.Len(t, result.Points, 1)
	assert.Equal(t, float64(1.5), result.Points[0].Value)

	result, err = svc.DashboardSeries(context.Background(), DashboardSeriesRequest{Metric: `up or vector(1)`})
	require.NoError(t, err)
	assert.False(t, result.Available)
	assert.Contains(t, result.Error, "unsupported metric")
}

func TestService_AuditListUsesConfiguredLogQL(t *testing.T) {
	const fixedQuery = `{event="admin_audit"}`
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[{"values":[["1000000000","{\"event\":\"admin_audit\",\"action\":\"config.get\",\"actor\":\"ops\",\"ok\":true}"]]}]}}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	config.ApplyDefaults(cfg)
	cfg.Admin.Stats.LokiURL = server.URL
	cfg.Admin.Stats.LokiQuery = fixedQuery
	svc, err := New(Options{Config: cfg})
	require.NoError(t, err)

	result, err := svc.AuditList(context.Background(), AuditListRequest{From: 1, To: 2, Limit: 10})
	require.NoError(t, err)
	assert.True(t, result.Available)
	assert.Equal(t, fixedQuery, gotQuery)
	require.Len(t, result.Events, 1)
	assert.Equal(t, "config.get", result.Events[0].Action)
}

func TestService_SystemHealthReportsProbeFailure(t *testing.T) {
	svc, err := New(Options{Probes: []ComponentProbe{{
		Name:  "usage_store",
		Check: func(context.Context) error { return errors.New("unavailable") },
	}}})
	require.NoError(t, err)

	result, err := svc.SystemHealth(context.Background(), SystemHealthRequest{})
	require.NoError(t, err)
	assert.False(t, result.OK)
	assert.Contains(t, result.Components, SourceStatus{Name: "usage_store", Status: "error", Detail: "unavailable"})
}

func TestService_RuleListSortsChains(t *testing.T) {
	cfg := &config.Config{}
	cfg.RiskControl.Chains = map[string]config.ChainConfig{
		"ZETA":  {Policy: config.PolicyConfig{Target: risk.TargetACCEPT}},
		"ALPHA": {Policy: config.PolicyConfig{Target: risk.TargetREJECT}},
	}
	svc, err := New(Options{Config: cfg})
	require.NoError(t, err)
	result, err := svc.RuleList(context.Background(), RuleListRequest{})
	require.NoError(t, err)
	require.Len(t, result.Chains, 2)
	assert.Equal(t, "ALPHA", result.Chains[0].Name)
	assert.Equal(t, "ZETA", result.Chains[1].Name)
}

func TestNormalizeSeriesRangeRejectsOversizedRange(t *testing.T) {
	_, _, _, err := normalizeSeriesRange(1, 1+int64((8*24*time.Hour)/time.Second), 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "7 days")
}
