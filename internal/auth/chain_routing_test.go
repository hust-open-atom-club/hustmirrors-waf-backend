package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

func boolPtr(v bool) *bool { return &v }

// missingPowChain mirrors the shipped config: a tokenless protected request
// jumps from INPUT into RISK_CHECK, whose policy is stricter than INPUT's.
func missingPowChain(t *testing.T) *risk.Engine {
	t.Helper()
	m, err := risk.CompileMatcher(risk.MatchConfig{PowStatus: "missing", IsProtected: boolPtr(true)})
	require.NoError(t, err)
	e, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name: "INPUT",
			Rules: []risk.Rule{{
				Name: "missing pow risk check", Match: m,
				Target: risk.TargetJUMP, Chain: "RISK_CHECK",
			}},
			Policy: risk.Policy{Target: risk.TargetRATELIMIT, LimitRate: "512k", Reason: "default_unverified_slow"},
		},
		"RISK_CHECK": {
			Name:   "RISK_CHECK",
			Policy: risk.Policy{Target: risk.TargetRATELIMIT, LimitRate: "128k", Reason: "normal_unverified_slow"},
		},
	})
	require.NoError(t, err)
	return e
}

// TestVerify_TokenlessRequestReachesRiskCheckChain locks the routing contract
// for tokenless protected requests: pow_status must arrive at the engine as
// "missing" so the JUMP rule fires and the decision comes from RISK_CHECK.
// It previously arrived as "", which made every pow_status=missing rule —
// including this jump — silently unmatchable, so an IP could keep pulling at
// the INPUT policy's 512k forever instead of being slowed and then blocked.
func TestVerify_TokenlessRequestReachesRiskCheckChain(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	svc, _, _, _ := makeTestServiceWithEngine(t, cfg, missingPowChain(t))

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
	})
	require.True(t, res.Allowed, "reason=%s", res.Reason)
	assert.Equal(t, "RISK_CHECK", res.RiskChain, "the missing-pow rule must jump into RISK_CHECK")
	assert.Equal(t, "normal_unverified_slow", res.Reason)
	assert.Equal(t, "128k", res.LimitRate)
}

// TestVerify_TokenlessUnprotectedStillUsesInputPolicy guards the other side:
// a request the jump rule does not match must still be decided by INPUT.
func TestVerify_TokenlessUnprotectedStillUsesInputPolicy(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	svc, _, _, _ := makeTestServiceWithEngine(t, cfg, missingPowChain(t))

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/index.html", OriginalMethod: "GET", RealIP: "1.2.3.4",
	})
	require.True(t, res.Allowed, "reason=%s", res.Reason)
	assert.Equal(t, "INPUT", res.RiskChain)
	assert.Equal(t, "default_unverified_slow", res.Reason)
	assert.Equal(t, "512k", res.LimitRate)
}
