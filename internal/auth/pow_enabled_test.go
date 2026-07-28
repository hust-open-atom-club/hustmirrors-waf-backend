package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

// TestPowDisabled_SkipsVerification covers pow.enabled=false. The field had
// no readers, so disabling PoW changed nothing: requests were still denied,
// tokens still verified, quota still charged.
func TestPowDisabled_SkipsVerification(t *testing.T) {
	off := false

	t.Run("missing token is allowed", func(t *testing.T) {
		cfg := makeBaseConfig()
		cfg.Pow.Enabled = &off
		svc, _, _, _ := makeTestService(t, cfg)

		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		assert.True(t, res.Allowed)
		assert.Equal(t, ReasonPowDisabled, res.Reason)
		assert.Equal(t, DecisionPowDisabled, res.Decision)
	})

	t.Run("malformed token is not verified", func(t *testing.T) {
		cfg := makeBaseConfig()
		cfg.Pow.Enabled = &off
		svc, _, _, _ := makeTestService(t, cfg)

		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: "token=garbage&sign=nope", RealIP: "1.2.3.4",
		})
		assert.True(t, res.Allowed, "no verification runs, so nothing can fail")
		assert.Equal(t, ReasonPowDisabled, res.Reason)
	})

	t.Run("quota is not charged", func(t *testing.T) {
		cfg := makeBaseConfig()
		cfg.Pow.Enabled = &off
		svc, _, store, mint := makeTestService(t, cfg)

		payload := findValidCounterForDifficulty(t, pow.TokenPayload{
			Mode: "generic", Path: "/ubuntu.iso",
		}, 8)
		token, sign := mint(payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: "token=" + token + "&sign=" + sign, RealIP: "1.2.3.4",
		})
		require.True(t, res.Allowed)
		assert.Zero(t, res.Uses)

		_, err := store.Get(context.Background(), pow.ComputeSignID(&payload, sign, "generic"))
		assert.Error(t, err, "a token nobody verified must not consume its quota")
	})

	t.Run("risk engine still decides", func(t *testing.T) {
		// The point of pow.enabled=false rather than bypass_all.
		m, err := risk.CompileMatcher(risk.MatchConfig{PathPrefix: "/blocked"})
		require.NoError(t, err)
		engine, err := risk.NewEngine(risk.ChainMap{
			"INPUT": {
				Name: "INPUT",
				Rules: []risk.Rule{{
					Name: "block", Match: m,
					Target: risk.TargetREJECT, Status: 403, Reason: "blocked_path",
				}},
				Policy: risk.Policy{Target: risk.TargetACCEPT, Reason: "default_ok"},
			},
		})
		require.NoError(t, err)

		cfg := makeBaseConfig()
		cfg.Pow.Enabled = &off
		cfg.RiskControl.Enabled = true
		svc, _, _, _ := makeTestServiceWithEngine(t, cfg, engine)

		blocked := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/blocked/x.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		assert.False(t, blocked.Allowed, "disabling PoW must not disable risk rules")
		assert.Equal(t, "blocked_path", blocked.Reason)

		ok := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		assert.True(t, ok.Allowed)
		assert.Equal(t, "default_ok", ok.Reason)
	})
}

// TestPowEnabled_DefaultsOn: an omitted key must not read as false, which
// would ship a build that verifies nothing.
func TestPowEnabled_DefaultsOn(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.Enabled = nil
	svc, _, _, _ := makeTestService(t, cfg)

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
	})
	assert.False(t, res.Allowed, "a nil Enabled must behave as enabled")
	assert.Equal(t, ReasonMissingTokenOrSign, res.Reason)
}
