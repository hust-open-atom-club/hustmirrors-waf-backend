package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
)

// TestSignID_IdenticalAcrossVerifyPaths guards a split usage record.
//
// chargeQuotaForRiskAllow reads tokenRaw and sign off verifyCtx, but Verify
// never populated those fields, so the risk-allow path derived the sign id
// from an empty sign. The same token was therefore metered under two
// different keys depending on which path handled it, and the record the
// risk path wrote was unreachable under the id every other caller computes.
func TestSignID_IdenticalAcrossVerifyPaths(t *testing.T) {
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)

	verifyOnce := func(riskOn bool) AuthResult {
		cfg := makeBaseConfig()
		var svc *Service
		var mint func(pow.TokenPayload) (string, string)
		if riskOn {
			cfg.RiskControl.Enabled = true
			svc, _, _, mint = makeTestServiceWithEngine(t, cfg, exampleInputChain(t))
		} else {
			svc, _, _, mint = makeTestService(t, cfg)
		}
		token, sign := mint(payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: "token=" + token + "&sign=" + sign, RealIP: "1.2.3.4",
		})
		require.True(t, res.Allowed, "reason=%s", res.Reason)
		return res
	}

	powOnly := verifyOnce(false)
	risk := verifyOnce(true)

	assert.Equal(t, powOnly.SignID, risk.SignID,
		"one token must map to one usage record regardless of which path meters it")
	assert.NotEmpty(t, risk.SignID)
}

// TestSignID_RiskPathWritesReachableRecord checks the consequence rather
// than the symptom: the record the risk path creates must be findable under
// the sign id ComputeSignID produces, or the quota it charged is invisible
// to every other lookup.
func TestSignID_RiskPathWritesReachableRecord(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	svc, _, store, mint := makeTestServiceWithEngine(t, cfg, exampleInputChain(t))

	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	token, sign := mint(payload)

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + token + "&sign=" + sign, RealIP: "1.2.3.4",
	})
	require.True(t, res.Allowed, "reason=%s", res.Reason)

	want := pow.ComputeSignID(&payload, sign, "generic")
	rec, err := store.Get(context.Background(), want)
	require.NoError(t, err, "the charged record must exist under the canonical sign id")
	assert.Equal(t, 1, rec.Uses)
	assert.NotEmpty(t, rec.TokenHash,
		"token_hash comes from tokenRaw; empty means it was not passed through")
}
