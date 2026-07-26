package echo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/auth"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/matcher"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
)

func makeAuthSvc(t *testing.T) *auth.Service {
	t.Helper()
	c := &config.Config{}
	c.Pow.TokenParam = "token"
	c.Pow.SignParam = "sign"
	c.Pow.MaxTokenLength = 4096
	c.Pow.MaxSignLength = 128
	c.Pow.Algorithm = "sha256"
	c.Pow.PublicSalt = "test-salt"
	c.Pow.AllowEmptySalt = true
	c.Pow.Modes.IPBound.Enabled = true
	c.Pow.Modes.IPBound.MinDifficulty = 1
	c.Pow.Modes.IPBound.MaxDifficulty = 32
	c.Pow.Modes.IPBound.MaxTTLSeconds = 86400
	c.Pow.Modes.IPBound.RequireIP = true
	c.Pow.Modes.Generic.Enabled = true
	c.Pow.Modes.Generic.MinDifficulty = 1
	c.Pow.Modes.Generic.MaxDifficulty = 32
	c.Pow.Modes.Generic.MaxTTLSeconds = 1800
	c.Pow.Modes.Generic.MaxUses = 3
	c.Protection.ProtectedExtensions = []string{".iso"}
	c.Server.ReadTimeout = 2 * time.Second
	c.Server.WriteTimeout = 2 * time.Second

	m := matcher.NewComposite(matcher.NewExtensionMatcher(c.Protection.ProtectedExtensions), nil)
	store := memory.NewUsageStore()
	svc, err := auth.New(auth.Options{
		Config: c, Matcher: m, UsageStore: store,
		Logger: logging.NewNop(), Metrics: metrics.New(),
	})
	require.NoError(t, err)
	return svc
}

func TestServer_VerifyPow_NotProtected(t *testing.T) {
	svc := makeAuthSvc(t)
	s := NewMain(MainOptions{
		Config:  &config.Config{},
		Logger:  logging.NewNop(),
		Metrics: metrics.New(),
		AuthSvc: svc,
	})
	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Original-URI", "/index.html")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "allow", rec.Header().Get("X-Pow-Result"))
	assert.Equal(t, "not_protected", rec.Header().Get("X-Pow-Reason"))
}

func TestServer_VerifyPow_MissingToken(t *testing.T) {
	svc := makeAuthSvc(t)
	s := NewMain(MainOptions{Config: &config.Config{}, Logger: logging.NewNop(), Metrics: metrics.New(), AuthSvc: svc})
	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Original-URI", "/ubuntu.iso")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "deny", rec.Header().Get("X-Pow-Result"))
	assert.Equal(t, "missing_token_or_sign", rec.Header().Get("X-Pow-Error"))
}

func TestServer_Healthz(t *testing.T) {
	s := NewMain(MainOptions{Config: &config.Config{}, Logger: logging.NewNop()})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "ok", body["status"])
}

func TestServer_Readyz(t *testing.T) {
	s := NewMain(MainOptions{Config: &config.Config{}, Logger: logging.NewNop()})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_Whoami(t *testing.T) {
	// The ip_bound flow depends on this returning exactly the IP that
	// /verify_pow will compare the token against, so the precedence here
	// must match clientIP: X-Real-IP, then X-Forwarded-For, then RemoteAddr.
	cases := []struct {
		name       string
		realIP     string
		forwarded  string
		remoteAddr string
		want       string
	}{
		{
			name:       "prefers X-Real-IP",
			realIP:     "203.0.113.7",
			forwarded:  "198.51.100.1",
			remoteAddr: "192.0.2.1:1234",
			want:       "203.0.113.7",
		},
		{
			name:       "falls back to first X-Forwarded-For hop",
			forwarded:  "198.51.100.1, 10.0.0.1",
			remoteAddr: "192.0.2.1:1234",
			want:       "198.51.100.1",
		},
		{
			name:       "falls back to RemoteAddr without port",
			remoteAddr: "192.0.2.1:1234",
			want:       "192.0.2.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMain(MainOptions{Config: &config.Config{}, Logger: logging.NewNop()})
			req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
			if tc.realIP != "" {
				req.Header.Set("X-Real-IP", tc.realIP)
			}
			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			req.RemoteAddr = tc.remoteAddr

			rec := httptest.NewRecorder()
			s.Echo().ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			var body map[string]string
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
			assert.Equal(t, tc.want, body["ip"])
		})
	}
}

func TestServer_Admin_Ping_NoneAuth(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "none"
	asvc, err := admin.New(admin.Options{})
	require.NoError(t, err)
	s := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/system.ping", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_Admin_TokenAuth_Missing(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "token"
	cfg.Admin.Auth.Token = "secret"
	asvc, _ := admin.New(admin.Options{})
	s := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/system.ping", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestServer_Admin_TokenAuth_Valid(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "token"
	cfg.Admin.Auth.Token = "secret"
	asvc, _ := admin.New(admin.Options{})
	s := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/system.ping", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_Admin_CIDR_Allow(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "none"
	cfg.Admin.AllowCIDRs = []string{"127.0.0.1/32"}
	asvc, _ := admin.New(admin.Options{})
	s := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/system.ping", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	req2 := httptest.NewRequest(http.MethodPost, "/admin/api/system.ping", strings.NewReader("{}"))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "10.0.0.1:12345"
	rec2 := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusForbidden, rec2.Code)
}

func TestServer_Admin_ConfigValidate(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "none"
	asvc, _ := admin.New(admin.Options{})
	s := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})

	body := `{"config_yaml":"pow:\n  modes:\n    ip_bound:\n      enabled: true\n      min_difficulty: 22\n      max_difficulty: 28\n      max_ttl_seconds: 86400\n"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/config.validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, true, resp["ok"])
}

func TestServer_Admin_SystemInfo(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "none"
	asvc, _ := admin.New(admin.Options{})
	s := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/system.info", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_Admin_RulePreview_NoEngine(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "none"
	asvc, _ := admin.New(admin.Options{})
	s := NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: asvc})
	body := `{"request":{"path":"/x.iso","is_protected":true,"pow_status":"missing"}}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/rule.preview", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_BearerToken(t *testing.T) {
	assert.Equal(t, "abc", bearerToken("Bearer abc"))
	assert.Equal(t, "", bearerToken("Basic abc"))
	assert.Equal(t, "", bearerToken(""))
}

func TestServer_ClientIP(t *testing.T) {
	s := NewMain(MainOptions{Config: &config.Config{}, Logger: logging.NewNop()})
	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Real-IP", "9.9.9.9")
	c := s.Echo().NewContext(req, httptest.NewRecorder())
	assert.Equal(t, "9.9.9.9", clientIP(c))

	req2 := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req2.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	c2 := s.Echo().NewContext(req2, httptest.NewRecorder())
	assert.Equal(t, "1.2.3.4", clientIP(c2))
}

func TestServer_IPAllowed(t *testing.T) {
	assert.True(t, ipAllowed("127.0.0.1", []string{"127.0.0.1/32"}))
	assert.True(t, ipAllowed("10.1.2.3", []string{"10.0.0.0/8"}))
	assert.False(t, ipAllowed("8.8.8.8", []string{"10.0.0.0/8"}))
	assert.False(t, ipAllowed("not-an-ip", []string{"10.0.0.0/8"}))
}

func TestServer_ShutdownWithoutStart(t *testing.T) {
	s := NewMain(MainOptions{Config: &config.Config{}, Logger: logging.NewNop()})
	require.NoError(t, s.Shutdown(context.Background()))
}
