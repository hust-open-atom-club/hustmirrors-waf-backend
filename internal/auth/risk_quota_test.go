package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

// acceptOnValidPow builds the INPUT chain from config.example.yaml:
// a valid token is accepted at full speed.
func acceptOnValidPow(t *testing.T) *risk.Engine {
	t.Helper()
	m, err := risk.CompileMatcher(risk.MatchConfig{PowStatus: "valid"})
	require.NoError(t, err)
	e, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name: "INPUT",
			Rules: []risk.Rule{{
				Name: "allow valid pow full speed", Match: m,
				Target: risk.TargetACCEPT, LimitRate: "0",
				Reason: "valid_pow_full_speed",
			}},
			Policy: risk.Policy{Target: risk.TargetRATELIMIT, LimitRate: "512k", Reason: "slow"},
		},
	})
	require.NoError(t, err)
	return e
}

// TestRiskAccept_ChargesGenericQuota covers a full bypass of max_uses.
//
// The risk engine ran before the PoW-only path and returned on ACCEPT, so
// a rule matching pow_status=valid honoured the token without ever
// charging its usage record. Since that rule is in the shipped example
// config, any deployment with risk_control enabled had no working quota.
func TestRiskAccept_ChargesGenericQuota(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	cfg.Pow.Modes.Generic.MaxUses = 1

	svc, _, _, mint := makeTestServiceWithEngine(t, cfg, acceptOnValidPow(t))
	p := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	tok, sign := mint(p)

	req := AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + tok + "&sign=" + sign, RealIP: "1.2.3.4",
	}

	first := svc.Verify(context.Background(), req)
	require.True(t, first.Allowed, "reason=%s", first.Reason)
	assert.Equal(t, 1, first.Uses, "the allow path must report the charge it made")
	assert.Equal(t, 1, first.MaxUses)
	assert.NotEmpty(t, first.SignID, "sign id must reach the response headers")

	allowed := 1
	for i := 0; i < 9; i++ {
		if svc.Verify(context.Background(), req).Allowed {
			allowed++
		}
	}
	assert.Equal(t, 1, allowed, "max_uses=1 must permit exactly one download")

	last := svc.Verify(context.Background(), req)
	assert.Equal(t, ReasonUsedUp, last.Reason)
}

// TestRiskAccept_IPBoundIsNotCharged guards the opposite direction:
// ip_bound has no usage record, so the quota logic must leave it alone.
func TestRiskAccept_IPBoundIsNotCharged(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true

	svc, _, _, mint := makeTestServiceWithEngine(t, cfg, acceptOnValidPow(t))
	p := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "ip_bound", Path: "/ubuntu.iso", IP: "1.2.3.4",
	}, 8)
	tok, sign := mint(p)

	req := AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + tok + "&sign=" + sign, RealIP: "1.2.3.4",
	}
	for i := 0; i < 5; i++ {
		res := svc.Verify(context.Background(), req)
		require.True(t, res.Allowed, "ip_bound is unmetered; reason=%s", res.Reason)
	}
}

// TestRiskAccept_TokenlessRequestIsNotCharged ensures a request the engine
// accepts on other grounds (metadata path, non-protected) is unaffected.
func TestRiskAccept_TokenlessRequestIsNotCharged(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true

	e, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: risk.TargetACCEPT, Reason: "metadata"},
		},
	})
	require.NoError(t, err)

	svc, _, _, _ := makeTestServiceWithEngine(t, cfg, e)
	for i := 0; i < 3; i++ {
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu/Packages", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		require.True(t, res.Allowed)
		assert.Zero(t, res.Uses, "a request with no token has no quota to charge")
	}
}
