package echo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/auth"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
)

func TestWriteAuthResult_DecisionHeader(t *testing.T) {
	s := NewMain(MainOptions{Config: &config.Config{}, Logger: logging.NewNop()})

	t.Run("allow verified", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c := s.Echo().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		writeAuthResult(c, auth.AuthResult{Allowed: true, HTTPStatus: 200, Reason: "generic_valid", Mode: "generic", Decision: "verified"})
		assert.Equal(t, "allow", rec.Header().Get("X-Pow-Result"))
		assert.Equal(t, "verified", rec.Header().Get("X-Pow-Decision"))
		assert.Equal(t, "generic", rec.Header().Get("X-Pow-Mode"))
	})

	t.Run("allow unverified_slow", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c := s.Echo().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		writeAuthResult(c, auth.AuthResult{Allowed: true, HTTPStatus: 200, Reason: "metadata_full_speed", LimitRate: "512k", Decision: "unverified_slow"})
		assert.Equal(t, "512k", rec.Header().Get("X-Pow-Limit-Rate"))
		assert.Equal(t, "unverified_slow", rec.Header().Get("X-Pow-Decision"))
	})

	t.Run("deny", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c := s.Echo().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		writeAuthResult(c, auth.AuthResult{Allowed: false, HTTPStatus: 403, Reason: "sign_mismatch", ErrorHeader: "sign_mismatch", Decision: "denied"})
		assert.Equal(t, 403, rec.Code)
		assert.Equal(t, "deny", rec.Header().Get("X-Pow-Result"))
		assert.Equal(t, "sign_mismatch", rec.Header().Get("X-Pow-Error"))
		assert.Equal(t, "denied", rec.Header().Get("X-Pow-Decision"))
	})

	t.Run("dry_run", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c := s.Echo().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		writeAuthResult(c, auth.AuthResult{Allowed: true, HTTPStatus: 200, Reason: "dry_run_allow", Decision: "dry_run", DryRunOriginalError: "missing_token_or_sign"})
		assert.Equal(t, "dry_run", rec.Header().Get("X-Pow-Decision"))
		assert.Equal(t, "missing_token_or_sign", rec.Header().Get("X-Pow-Dry-Run-Original-Error"))
	})
}

func TestDecisionConstants(t *testing.T) {
	require.Equal(t, "verified", auth.DecisionVerified)
	require.Equal(t, "unverified_slow", auth.DecisionUnverifiedSlow)
	require.Equal(t, "unverified_very_slow", auth.DecisionUnverifiedVerySlow)
	require.Equal(t, "not_protected", auth.DecisionNotProtected)
	require.Equal(t, "denied", auth.DecisionDenied)
	require.Equal(t, "bypass", auth.DecisionBypass)
	require.Equal(t, "dry_run", auth.DecisionDryRun)
}
