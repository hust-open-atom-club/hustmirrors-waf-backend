package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
)

// mutateEncoding returns wire encodings that all decode to the same
// payload. A verifier that treats these as distinct tokens is counting
// encodings rather than proofs of work.
func mutateEncoding(t *testing.T, p pow.TokenPayload) map[string]string {
	t.Helper()
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	withSuffix := func(b []byte) string {
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return map[string]string{
		"canonical":        withSuffix(raw),
		"padded base64":    base64.URLEncoding.EncodeToString(raw),
		"trailing space":   withSuffix(append(append([]byte{}, raw...), ' ')),
		"trailing newline": withSuffix(append(append([]byte{}, raw...), '\n')),
		"trailing tab":     withSuffix(append(append([]byte{}, raw...), '\t')),
	}
}

// TestGenericMode_MaxUsesSurvivesReencoding is the regression guard for a
// complete bypass of the generic-mode usage cap.
//
// sign_id used to be derived from the raw token bytes. JSON tolerates
// trailing whitespace and base64url accepts both padded and unpadded
// input, so a single PoW solution could be re-encoded into unlimited
// distinct tokens, each of which opened its own usage record. max_uses
// counted encodings, not work.
func TestGenericMode_MaxUsesSurvivesReencoding(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.Modes.Generic.MaxUses = 1
	svc, _, _, _ := makeTestService(t, cfg)

	p := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	p.Version = 1
	p.Algorithm = "sha256"
	if p.Salt == "" {
		p.Salt = cfg.Pow.PublicSalt
	}
	sign := pow.ComputeSign(&p)

	var signIDs []string
	allowed := 0
	for name, token := range mutateEncoding(t, p) {
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI:    "/ubuntu.iso",
			OriginalMethod: "GET",
			OriginalArgs:   "token=" + token + "&sign=" + sign,
			RealIP:         "1.2.3.4",
		})
		if res.Allowed {
			allowed++
		}
		if res.SignID != "" {
			signIDs = append(signIDs, res.SignID)
		}
		t.Logf("%-18s allowed=%v reason=%s", name, res.Allowed, res.Reason)
	}

	assert.Equal(t, 1, allowed,
		"max_uses=1 must permit exactly one download regardless of encoding")

	require.NotEmpty(t, signIDs)
	for _, id := range signIDs {
		assert.Equal(t, signIDs[0], id,
			"every encoding of one payload must map to a single usage record")
	}
}

// TestGenericMode_MaxUsesNotAmplifiable scales the same attack up, so a
// partial fix that merely normalises a couple of known cases still fails.
func TestGenericMode_MaxUsesNotAmplifiable(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.Modes.Generic.MaxUses = 1
	svc, _, _, _ := makeTestService(t, cfg)

	p := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	p.Version = 1
	p.Algorithm = "sha256"
	if p.Salt == "" {
		p.Salt = cfg.Pow.PublicSalt
	}
	sign := pow.ComputeSign(&p)
	raw, err := json.Marshal(p)
	require.NoError(t, err)

	const attempts = 100
	allowed := 0
	for i := 0; i < attempts; i++ {
		mutated := append(append([]byte{}, raw...), []byte(strings.Repeat(" ", i))...)
		token := base64.RawURLEncoding.EncodeToString(mutated)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI:    "/ubuntu.iso",
			OriginalMethod: "GET",
			OriginalArgs:   "token=" + token + "&sign=" + sign,
			RealIP:         "1.2.3.4",
		})
		if res.Allowed {
			allowed++
		}
	}

	assert.Equal(t, 1, allowed,
		"one PoW computation must yield one download, not %d", attempts)
}
