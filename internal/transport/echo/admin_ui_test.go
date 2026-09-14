package echo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
)

func newAdminUIServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.Admin.Auth.Token = ""
	svc, err := admin.New(admin.Options{Config: cfg})
	require.NoError(t, err)
	return NewAdmin(AdminOptions{Config: cfg, Logger: logging.NewNop(), AdminSvc: svc})
}

func TestAdminUI_FaviconDoesNot404(t *testing.T) {
	server := newAdminUIServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	rec := httptest.NewRecorder()
	server.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestAdminUI_RedirectAndSecurityHeaders(t *testing.T) {
	server := newAdminUIServer(t, nil)

	redirectReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	redirectRec := httptest.NewRecorder()
	server.Echo().ServeHTTP(redirectRec, redirectReq)
	require.Equal(t, http.StatusPermanentRedirect, redirectRec.Code)
	assert.Equal(t, "/admin/", redirectRec.Header().Get("Location"))

	indexReq := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	indexRec := httptest.NewRecorder()
	server.Echo().ServeHTTP(indexRec, indexReq)
	require.Equal(t, http.StatusOK, indexRec.Code)
	assert.Contains(t, indexRec.Header().Get("Content-Type"), "text/html")
	assert.Equal(t, "no-store", indexRec.Header().Get("Cache-Control"))
	assert.Equal(t, "nosniff", indexRec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", indexRec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", indexRec.Header().Get("Referrer-Policy"))
	assert.Contains(t, indexRec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	assert.Contains(t, indexRec.Body.String(), "Mirrors WAF")
}

func TestAdminUI_AssetCachingAndSPAFallback(t *testing.T) {
	server := newAdminUIServer(t, nil)

	indexReq := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	indexRec := httptest.NewRecorder()
	server.Echo().ServeHTTP(indexRec, indexReq)
	require.Equal(t, http.StatusOK, indexRec.Code)

	body := indexRec.Body.String()
	assetStart := strings.Index(body, "/admin/assets/")
	require.NotEqual(t, -1, assetStart)
	assetEnd := strings.IndexAny(body[assetStart:], `"'`)
	require.Greater(t, assetEnd, 0)
	assetPath := body[assetStart : assetStart+assetEnd]

	assetReq := httptest.NewRequest(http.MethodGet, assetPath, nil)
	assetRec := httptest.NewRecorder()
	server.Echo().ServeHTTP(assetRec, assetReq)
	require.Equal(t, http.StatusOK, assetRec.Code)
	assert.Equal(t, "public, max-age=31536000, immutable", assetRec.Header().Get("Cache-Control"))

	spaReq := httptest.NewRequest(http.MethodGet, "/admin/rules", nil)
	spaRec := httptest.NewRecorder()
	server.Echo().ServeHTTP(spaRec, spaReq)
	require.Equal(t, http.StatusOK, spaRec.Code)
	assert.Contains(t, spaRec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, spaRec.Body.String(), "Mirrors WAF")

	missingAssetReq := httptest.NewRequest(http.MethodGet, "/admin/assets/missing.js", nil)
	missingAssetRec := httptest.NewRecorder()
	server.Echo().ServeHTTP(missingAssetRec, missingAssetReq)
	assert.Equal(t, http.StatusNotFound, missingAssetRec.Code)
}

func TestAdminUI_DoesNotSwallowAdminAPIPaths(t *testing.T) {
	server := newAdminUIServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/api/does-not-exist", nil)
	rec := httptest.NewRecorder()
	server.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "Mirrors WAF")
}

func TestAdminUI_HonoursCIDRAllowList(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.AllowCIDRs = []string{"10.0.0.0/8"}
	server := newAdminUIServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.Header.Set("X-Real-IP", "192.0.2.10")
	rec := httptest.NewRecorder()
	server.Echo().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
