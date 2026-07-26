package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
)

func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server:
  listen: "127.0.0.1:0"
  read_timeout: "2s"
  write_timeout: "2s"
  shutdown_timeout: "2s"

pow:
  enabled: true
  dry_run: false
  bypass_all: false
  token_param: "token"
  sign_param: "sign"
  max_token_length: 4096
  max_sign_length: 128
  algorithm: "sha256"
  public_salt: "test-salt"
  allow_empty_salt: true
  modes:
    ip_bound:
      enabled: true
      min_difficulty: 1
      max_difficulty: 32
      max_ttl_seconds: 86400
      require_ip: true
    generic:
      enabled: true
      min_difficulty: 1
      max_difficulty: 32
      max_ttl_seconds: 1800
      max_uses: 3

protection:
  protected_extensions:
    - ".iso"
    - ".img"
  protected_paths: []
  excluded_paths:
    - "^/static/"

storage:
  driver: "memory"
  counter_driver: "memory"

risk_control:
  enabled: false

admin:
  enabled: false

logging:
  level: "info"
  format: "json"

cleanup:
  enabled: false
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	return path
}

func TestBuild_StartShutdown(t *testing.T) {
	path := writeTestConfig(t)
	cfg, err := config.Load(path)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a, err := Build(ctx, cfg)
	require.NoError(t, err)
	defer func() {
		sctx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer sCancel()
		_ = a.Shutdown(sctx)
	}()

	require.NotNil(t, a.mainSrv)
	assert.Nil(t, a.adminSrv)

	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Original-URI", "/x.txt")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()
	a.mainSrv.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "allow", rec.Header().Get("X-Pow-Result"))

	req2 := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req2.Header.Set("X-Original-URI", "/x.iso")
	req2.Header.Set("X-Real-IP", "1.2.3.4")
	rec2 := httptest.NewRecorder()
	a.mainSrv.Echo().ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusForbidden, rec2.Code)
	assert.Equal(t, "missing_token_or_sign", rec2.Header().Get("X-Pow-Error"))
}

func TestBuild_MissingConfig(t *testing.T) {
	_, err := Build(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config is nil")
}

// TestBuild_BadProtectedPathRegexIsFatal covers the case where a regex
// reaches Build without having been validated. Previously this degraded to
// extension-only matching, leaving every regex-protected path unguarded
// while the service reported a clean startup.
func TestBuild_BadProtectedPathRegexIsFatal(t *testing.T) {
	path := writeTestConfig(t)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	cfg.Protection.ProtectedPaths = []string{"^/ubuntu/(unclosed"}

	_, err = Build(context.Background(), cfg)
	require.Error(t, err, "an uncompilable protected_paths regex must not start the service")
	assert.Contains(t, err.Error(), "protected_paths")
}

// TestBuild_BadExcludedPathRegexIsFatal is the mirror case: silently
// dropping the exclusion list would subject exempt paths to PoW.
func TestBuild_BadExcludedPathRegexIsFatal(t *testing.T) {
	path := writeTestConfig(t)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	cfg.Protection.ExcludedPaths = []string{"*bad"}

	_, err = Build(context.Background(), cfg)
	require.Error(t, err, "an uncompilable excluded_paths regex must not start the service")
	assert.Contains(t, err.Error(), "excluded_paths")
}

// TestBuild_RedisUsageDriver covers storage.driver=redis end to end. The
// redis UsageStore was fully implemented and tested but unreachable: config
// validation rejected the driver, and buildStorage only constructed it under
// a condition that could never hold.
func TestBuild_RedisUsageDriver(t *testing.T) {
	mr := miniredis.RunT(t)

	path := writeTestConfig(t)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	cfg.Storage.Driver = "redis"
	cfg.Storage.CounterDriver = "redis"
	cfg.Storage.Redis.Addr = mr.Addr()
	require.NoError(t, config.Validate(cfg), "redis must be an accepted storage.driver")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, err := Build(ctx, cfg)
	require.NoError(t, err)
	defer func() {
		sctx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer sCancel()
		_ = a.Shutdown(sctx)
	}()

	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Original-URI", "/ubuntu.iso")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()
	a.mainSrv.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "missing_token_or_sign", rec.Header().Get("X-Pow-Error"))
}

// TestBuild_RedisUsageDriver_UnreachableIsFatal pins the asymmetry between
// the two redis roles. Counters may silently degrade to memory, but usage
// records are authoritative - falling back would drop the max_uses cap and
// let every generic token be replayed without limit.
func TestBuild_RedisUsageDriver_UnreachableIsFatal(t *testing.T) {
	path := writeTestConfig(t)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	cfg.Storage.Driver = "redis"
	// Port 1 is reserved and never listening.
	cfg.Storage.Redis.Addr = "127.0.0.1:1"

	_, err = Build(context.Background(), cfg)
	require.Error(t, err, "an unreachable redis must not silently degrade the usage store")
	assert.Contains(t, err.Error(), "redis")
}

func TestBuild_RiskControlEnabled(t *testing.T) {
	path := writeTestConfig(t)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	cfg.RiskControl.Enabled = true
	cfg.RiskControl.Chains = map[string]config.ChainConfig{
		"INPUT": {
			Policy: config.PolicyConfig{Target: "RATE_LIMIT", LimitRate: "512k", Reason: "default_slow"},
			Rules: []config.RuleConfig{
				{Name: "metadata", Match: config.MatchConfig{PathRegex: `^/.+/Packages$`}, Target: "ACCEPT", LimitRate: "0", Reason: "metadata"},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, err := Build(ctx, cfg)
	require.NoError(t, err)
	defer func() {
		sctx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer sCancel()
		_ = a.Shutdown(sctx)
	}()

	// Metadata path should ACCEPT via risk engine.
	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Original-URI", "/ubuntu/Packages")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()
	a.mainSrv.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "metadata", rec.Header().Get("X-Pow-Reason"))
}
