package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

// exampleInputChain mirrors the INPUT chain of config.example.yaml: reject
// the bad statuses, accept a valid token, rate-limit everything else.
//
// It deliberately includes the reject rule. A chain with only the accept
// rule would let a rejected token fall through to the policy and be
// rate-limited, which would be a property of the test chain rather than of
// the code under test.
func exampleInputChain(t *testing.T) *risk.Engine {
	t.Helper()
	accept, err := risk.CompileMatcher(risk.MatchConfig{PowStatus: "valid"})
	require.NoError(t, err)
	rejectBad, err := risk.CompileMatcher(risk.MatchConfig{
		PowStatusIn: []string{"invalid", "expired", "used_up", "mode_disabled"},
	})
	require.NoError(t, err)
	e, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name: "INPUT",
			Rules: []risk.Rule{
				{
					Name: "reject invalid pow", Match: rejectBad,
					Target: risk.TargetREJECT, Status: 403, Reason: "invalid_pow",
				},
				{
					Name: "allow valid pow full speed", Match: accept,
					Target: risk.TargetACCEPT, LimitRate: "0",
					Reason: "valid_pow_full_speed",
				},
			},
			Policy: risk.Policy{Target: risk.TargetRATELIMIT, LimitRate: "512k", Reason: "slow"},
		},
	})
	require.NoError(t, err)
	return e
}

// TestClassifyPoW_RejectsTTLBeyondMaxTTL guards a divergence between the
// two verification paths.
//
// max_ttl_seconds caps how long a self-issued token may live. The check
// lives in checkTime, which only verifyPoWOnly used to call, so classifyPoW
// reported a one-year token as "valid" and the risk engine honoured it -
// while the PoW-only path rejected the very same token as ttl_too_long.
func TestClassifyPoW_RejectsTTLBeyondMaxTTL(t *testing.T) {
	cfg := makeBaseConfig() // generic max_ttl_seconds = 1800
	svc, fc, _, mint := makeTestService(t, cfg)
	now := fc.Now().Unix()

	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
		Timestamp: now, ExpiresAt: now + 365*24*3600,
	}, 8)
	token, sign := mint(payload)

	_, status, mode := svc.classifyPoW(context.Background(), token, sign, "/ubuntu.iso", "1.2.3.4")
	assert.Equal(t, "generic", mode)
	assert.NotEqual(t, "valid", status,
		"a token whose TTL exceeds max_ttl_seconds must not classify as valid")

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + token + "&sign=" + sign, RealIP: "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonTTLTooLong, res.Reason)
}

// TestClassifyPoW_RejectsDisabledMode is the second half of the same
// divergence. modeConfig's bool reports only "this is a known mode name";
// whether the operator enabled it is a separate field that classifyPoW
// never read. A generic token therefore stayed usable through the risk
// engine after generic mode had been switched off.
func TestClassifyPoW_RejectsDisabledMode(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.Modes.Generic.Enabled = false
	cfg.Pow.Modes.IPBound.Enabled = true

	svc, _, _, mint := makeTestService(t, cfg)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	token, sign := mint(payload)

	_, status, _ := svc.classifyPoW(context.Background(), token, sign, "/ubuntu.iso", "1.2.3.4")
	assert.Equal(t, "mode_disabled", status,
		"a disabled mode is neither valid nor a forged token")

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + token + "&sign=" + sign, RealIP: "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonModeDisabled, res.Reason)
}

// TestVerifyPaths_AgreeOnRejection asserts the property that matters, rather
// than the individual bugs: if the PoW-only path rejects a token, enabling
// risk control must not turn that into an allow.
//
// Three separate bugs have been instances of this property being violated
// (empty X-Real-IP, TTL over the cap, disabled mode), so it is worth
// checking directly - a future check added to one path and not the other
// will fail here.
func TestVerifyPaths_AgreeOnRejection(t *testing.T) {
	cases := []struct {
		name    string
		disable bool  // turn generic mode off
		ttl     int64 // token lifetime in seconds; 0 uses the mint default
	}{
		{name: "ttl beyond max_ttl", ttl: 365 * 24 * 3600},
		{name: "generic mode disabled", disable: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mk := func(riskOn bool) (bool, string) {
				cfg := makeBaseConfig()
				if c.disable {
					cfg.Pow.Modes.Generic.Enabled = false
					cfg.Pow.Modes.IPBound.Enabled = true
				}
				var engine *risk.Engine
				if riskOn {
					cfg.RiskControl.Enabled = true
					engine = exampleInputChain(t)
				}
				svc, fc, _, mint := makeTestServiceWithEngine(t, cfg, engine)
				now := fc.Now().Unix()

				base := pow.TokenPayload{Mode: "generic", Path: "/ubuntu.iso"}
				if c.ttl > 0 {
					base.Timestamp = now
					base.ExpiresAt = now + c.ttl
				}
				payload := findValidCounterForDifficulty(t, base, 8)
				token, sign := mint(payload)

				res := svc.Verify(context.Background(), AuthRequest{
					OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
					OriginalArgs: "token=" + token + "&sign=" + sign, RealIP: "1.2.3.4",
				})
				return res.Allowed, res.Reason
			}

			powOnlyAllowed, powOnlyReason := mk(false)
			riskAllowed, riskReason := mk(true)

			require.False(t, powOnlyAllowed,
				"precondition: the PoW-only path must reject this token (got %s)", powOnlyReason)
			assert.False(t, riskAllowed,
				"risk control must not admit a token the PoW-only path rejects as %s (risk said %s)",
				powOnlyReason, riskReason)
		})
	}
}
