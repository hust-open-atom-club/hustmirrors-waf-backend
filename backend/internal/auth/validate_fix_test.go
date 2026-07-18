package auth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
)

func encodeToken(t *testing.T, p pow.TokenPayload) string {
	t.Helper()
	b, _ := json.Marshal(p)
	return base64URLEncode(string(b))
}

// TestVerify_ValidatePayloadNowEnforced covers the bug fix: verifyPoWOnly
// previously skipped pow.ValidatePayload, so bad salt / bad counter / bad
// algorithm tokens slipped through. They must now be rejected.
func TestVerify_ValidatePayloadNowEnforced(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)

	t.Run("bad salt rejected", func(t *testing.T) {
		payload := findValidCounterForDifficulty(t, pow.TokenPayload{
			Mode: "generic", Path: "/ubuntu.iso",
		}, 8)
		payload.Salt = "rogue-salt-not-in-allowlist"
		token, sign := mint(payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: "token=" + token + "&sign=" + sign,
			RealIP:       "1.2.3.4",
		})
		assert.False(t, res.Allowed)
		assert.Equal(t, ReasonInvalidSalt, res.Reason)
	})

	t.Run("bad counter rejected", func(t *testing.T) {
		payload := findValidCounterForDifficulty(t, pow.TokenPayload{
			Mode: "generic", Path: "/ubuntu.iso",
		}, 8)
		payload.Counter = "has space"
		token := encodeToken(t, payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: "token=" + token + "&sign=" + pow.ComputeSign(&payload),
			RealIP:       "1.2.3.4",
		})
		assert.False(t, res.Allowed)
		assert.Equal(t, ReasonInvalidCounter, res.Reason)
	})

	t.Run("bad algorithm rejected", func(t *testing.T) {
		payload := findValidCounterForDifficulty(t, pow.TokenPayload{
			Mode: "generic", Path: "/ubuntu.iso",
		}, 8)
		payload.Algorithm = "md5"
		token := encodeToken(t, payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: "token=" + token + "&sign=" + pow.ComputeSign(&payload),
			RealIP:       "1.2.3.4",
		})
		assert.False(t, res.Allowed)
		assert.Equal(t, ReasonUnsupportedAlgorithm, res.Reason)
	})

	t.Run("generic with ip field rejected", func(t *testing.T) {
		payload := findValidCounterForDifficulty(t, pow.TokenPayload{
			Mode: "generic", Path: "/ubuntu.iso",
		}, 8)
		payload.IP = "1.2.3.4"
		token := encodeToken(t, payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: "token=" + token + "&sign=" + pow.ComputeSign(&payload),
			RealIP:       "1.2.3.4",
		})
		assert.False(t, res.Allowed)
		assert.Equal(t, ReasonIPForbidden, res.Reason)
	})

	t.Run("bad version rejected", func(t *testing.T) {
		payload := findValidCounterForDifficulty(t, pow.TokenPayload{
			Mode: "generic", Path: "/ubuntu.iso",
		}, 8)
		payload.Version = 99
		token := encodeToken(t, payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: "token=" + token + "&sign=" + pow.ComputeSign(&payload),
			RealIP:       "1.2.3.4",
		})
		assert.False(t, res.Allowed)
		assert.Equal(t, ReasonUnsupportedVersion, res.Reason)
	})
}

func TestVerify_ErrorHeaderAlwaysSet(t *testing.T) {
	svc, _, _, _ := makeTestService(t, nil)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "", RealIP: "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.NotEmpty(t, res.ErrorHeader)
	assert.Equal(t, res.Reason, res.ErrorHeader)
}

func TestVerify_DecisionAlwaysSet(t *testing.T) {
	svc, _, _, _ := makeTestService(t, nil)

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "", RealIP: "1.2.3.4",
	})
	assert.NotEmpty(t, res.Decision)
	assert.Equal(t, DecisionDenied, res.Decision)

	res = svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/index.html", OriginalMethod: "GET",
		OriginalArgs: "", RealIP: "1.2.3.4",
	})
	assert.NotEmpty(t, res.Decision)
	assert.Equal(t, DecisionNotProtected, res.Decision)
}
