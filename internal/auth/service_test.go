package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/clock"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/matcher"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
)

func makeTestService(t *testing.T, cfg *config.Config) (*Service, *clock.Fake, *memory.UsageStore, func(payload pow.TokenPayload) (token, sign string)) {
	t.Helper()
	return makeTestServiceWithEngine(t, cfg, nil)
}

// makeTestServiceWithEngine is makeTestService with a risk engine attached,
// for the paths that only run when risk control is enabled.
func makeTestServiceWithEngine(t *testing.T, cfg *config.Config, engine *risk.Engine) (*Service, *clock.Fake, *memory.UsageStore, func(payload pow.TokenPayload) (token, sign string)) {
	t.Helper()
	if cfg == nil {
		cfg = makeBaseConfig()
	}
	m := matcher.NewComposite(
		matcher.NewExtensionMatcher(cfg.Protection.ProtectedExtensions),
		nil,
	)
	store := memory.NewUsageStore()
	fc := clock.NewFake()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fc.Set(now)
	svc, err := New(Options{
		Config: cfg, Matcher: m, UsageStore: store,
		Clock: fc, Logger: logging.NewNop(), Metrics: metrics.New(),
		RiskEngine: engine,
	})
	require.NoError(t, err)

	mint := func(payload pow.TokenPayload) (string, string) {
		payload.Version = 1
		payload.Algorithm = "sha256"
		// Only set ts/exp/d/cnt/salt when not already populated by the caller
		// (findValidCounterForDifficulty pre-populates these so that the
		// sign it produced matches the sign mint() recomputes).
		if payload.Timestamp == 0 {
			payload.Timestamp = fc.Now().Unix()
		}
		if payload.ExpiresAt == 0 {
			payload.ExpiresAt = payload.Timestamp + 600
		}
		if payload.Difficulty == 0 {
			payload.Difficulty = 1
		}
		if payload.Counter == "" {
			payload.Counter = "0"
		}
		if payload.Salt == "" {
			payload.Salt = cfg.Pow.PublicSalt
		}
		b, _ := json.Marshal(payload)
		token := base64URLEncode(string(b))
		sign := pow.ComputeSign(&payload)
		return token, sign
	}
	return svc, fc, store, mint
}

// findValidCounterForDifficulty brute-forces a cnt value that satisfies the
// given difficulty. The payload must already have every field that mint()
// would set populated, so that the hash computed here matches the sign
// mint() will produce.
func findValidCounterForDifficulty(t *testing.T, base pow.TokenPayload, difficulty int) pow.TokenPayload {
	t.Helper()
	base.Version = 1
	base.Algorithm = "sha256"
	base.Difficulty = difficulty
	if base.Salt == "" {
		base.Salt = "test-salt"
	}
	if base.Timestamp == 0 {
		base.Timestamp = 1735689600
	}
	if base.ExpiresAt == 0 {
		base.ExpiresAt = base.Timestamp + 600
	}
	for i := 0; i < 5_000_000; i++ {
		base.Counter = hexCounter(i)
		hash := sha256.Sum256([]byte(pow.BuildCanonicalInput(&base)))
		if pow.HasLeadingZeroBits(hash[:], difficulty) {
			return base
		}
	}
	t.Fatalf("could not find valid counter for difficulty %d", difficulty)
	return base
}

func hexCounter(n int) string {
	return hex.EncodeToString([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

func makeBaseConfig() *config.Config {
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
	c.Protection.ProtectedExtensions = []string{".iso", ".img", ".tar.gz"}
	return c
}

func base64URLEncode(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := []byte(s)
	out := make([]byte, 0, ((len(b)+2)/3)*4)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		var cnt int
		for j := 0; j < 3 && i+j < len(b); j++ {
			n |= uint32(b[i+j]) << (16 - 8*j)
			cnt++
		}
		for j := 0; j < cnt+1; j++ {
			out = append(out, alphabet[(n>>(18-6*j))&0x3F])
		}
	}
	return string(out)
}

func TestVerify_NotProtected(t *testing.T) {
	svc, _, _, _ := makeTestService(t, nil)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/index.html",
		OriginalMethod: "GET",
		OriginalArgs:   "",
		RealIP:         "1.2.3.4",
	})
	assert.True(t, res.Allowed)
	assert.Equal(t, 200, res.HTTPStatus)
	assert.Equal(t, ReasonNotProtected, res.Reason)
}

func TestVerify_MissingTokenOrSign(t *testing.T) {
	svc, _, _, _ := makeTestService(t, nil)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "",
		RealIP:         "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, 403, res.HTTPStatus)
	assert.Equal(t, ReasonMissingTokenOrSign, res.Reason)
}

func TestVerify_MalformedToken(t *testing.T) {
	svc, _, _, _ := makeTestService(t, nil)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "token=notvalid&sign=abc",
		RealIP:         "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonMalformedToken, res.Reason)
}

func TestVerify_PathMismatch(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	payload := pow.TokenPayload{Mode: "generic", Path: "/other.iso"}
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "token=" + token + "&sign=" + sign,
		RealIP:         "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonPathMismatch, res.Reason)
}

// TestVerify_IPBound_MissingRealIP covers the case where Nginx is not
// forwarding X-Real-IP. Blaming the client with a 403 ip_mismatch would be
// wrong and near-impossible to diagnose from the client side, so the
// request must fail closed as a server error with a distinct reason.
func TestVerify_IPBound_MissingRealIP(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "ip_bound", Path: "/ubuntu.iso", IP: "1.2.3.4",
	}, 8)
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "token=" + token + "&sign=" + sign,
		RealIP:         "",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, 500, res.HTTPStatus, "must be a server error, not a 403")
	assert.Equal(t, ReasonMissingRealIP, res.Reason)
	assert.NotEqual(t, ReasonIPMismatch, res.Reason,
		"must not be reported as a client-side IP mismatch")
}

// TestVerify_IPBound_MissingRealIP_NotRescuedByDryRun ensures the misconfig
// signal survives dry-run mode, which otherwise rewrites denials to allows.
// Silently serving traffic here would hide a broken deployment.
func TestVerify_IPBound_MissingRealIP_NotRescuedByDryRun(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.DryRun = true
	svc, _, _, mint := makeTestService(t, cfg)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "ip_bound", Path: "/ubuntu.iso", IP: "1.2.3.4",
	}, 8)
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "token=" + token + "&sign=" + sign,
		RealIP:         "",
	})
	assert.False(t, res.Allowed, "dry-run must not mask a proxy misconfiguration")
	assert.Equal(t, ReasonMissingRealIP, res.Reason)
}

// TestClassifyPoW_MissingRealIPIsUnverifiable pins the three-way
// distinction the risk engine depends on. An absent X-Real-IP is neither
// a forged token ("invalid") nor a checked one ("valid") - conflating it
// with either is a bug:
//   - as "invalid", risk rules punish clients for a proxy misconfiguration
//   - as "valid", REQUIRE_POW admits a token bound to another address,
//     because that path never reaches finalizeIPBound
func TestClassifyPoW_MissingRealIPIsUnverifiable(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "ip_bound", Path: "/ubuntu.iso", IP: "1.2.3.4",
	}, 8)
	token, sign := mint(payload)

	_, status, mode := svc.classifyPoW(context.Background(), token, sign, "/ubuntu.iso", "")
	assert.Equal(t, "ip_bound", mode)
	assert.Equal(t, "unverifiable", status,
		"an unverifiable binding must not be reported as valid or invalid")

	// A genuine mismatch, where realIP is present, still classifies invalid.
	_, status, _ = svc.classifyPoW(context.Background(), token, sign, "/ubuntu.iso", "9.9.9.9")
	assert.Equal(t, "invalid", status)

	// The matching case is unaffected.
	_, status, _ = svc.classifyPoW(context.Background(), token, sign, "/ubuntu.iso", "1.2.3.4")
	assert.Equal(t, "valid", status)
}

// TestVerify_RequirePow_IPBoundWithoutRealIPIsDenied is the end-to-end
// guard for the REQUIRE_POW path, which consumes classifyPoW's verdict
// directly and has no later gate. A token bound to a different address
// must never be admitted just because the proxy dropped X-Real-IP.
func TestVerify_RequirePow_IPBoundWithoutRealIPIsDenied(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	engine, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: risk.TargetREQUIREPOW, Reason: "need_pow"},
		},
	})
	require.NoError(t, err)

	svc, _, _, mint := makeTestServiceWithEngine(t, cfg, engine)
	// Bound to somebody else's address.
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "ip_bound", Path: "/ubuntu.iso", IP: "9.9.9.9",
	}, 8)
	token, sign := mint(payload)

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "token=" + token + "&sign=" + sign,
		RealIP:         "",
	})
	assert.False(t, res.Allowed,
		"an ip_bound token must never be accepted when its binding cannot be checked")
	assert.Equal(t, 500, res.HTTPStatus)
	assert.Equal(t, ReasonMissingRealIP, res.Reason)
}

func TestVerify_IPBoundValid(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "ip_bound", Path: "/ubuntu.iso", IP: "1.2.3.4",
	}, 8)
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "token=" + token + "&sign=" + sign,
		RealIP:         "1.2.3.4",
	})
	assert.True(t, res.Allowed, "should be allowed; reason=%s err=%s", res.Reason, res.ErrorHeader)
	assert.Equal(t, ReasonIPBoundValid, res.Reason)
	assert.Equal(t, "ip_bound", res.Mode)
}

func TestVerify_IPBoundIPMismatch(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "ip_bound", Path: "/ubuntu.iso", IP: "1.2.3.4",
	}, 8)
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "token=" + token + "&sign=" + sign,
		RealIP:         "9.9.9.9",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonIPMismatch, res.Reason)
}

func TestVerify_GenericValid_AndUsedUp(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	token, sign := mint(payload)
	args := "token=" + token + "&sign=" + sign

	for i := 1; i <= 3; i++ {
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
			OriginalArgs: args, RealIP: "1.2.3.4",
		})
		assert.True(t, res.Allowed, "call %d should be allowed", i)
		assert.Equal(t, i, res.Uses)
		assert.Equal(t, 3, res.MaxUses)
	}
	// 4th call: used up.
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: args, RealIP: "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonUsedUp, res.Reason)
}

func TestVerify_GenericHeadDoesNotConsume(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	token, sign := mint(payload)
	args := "token=" + token + "&sign=" + sign

	// First a HEAD: should not consume.
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "HEAD",
		OriginalArgs: args, RealIP: "1.2.3.4",
	})
	assert.True(t, res.Allowed)
	assert.Equal(t, 0, res.Uses, "HEAD must not consume")

	// First GET now uses 1.
	res = svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: args, RealIP: "1.2.3.4",
	})
	assert.True(t, res.Allowed)
	assert.Equal(t, 1, res.Uses)
}

func TestVerify_SignMismatch(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	payload := pow.TokenPayload{Mode: "generic", Path: "/ubuntu.iso", Difficulty: 1}
	token, _ := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + token + "&sign=0000000000000000000000000000000000000000000000000000000000000000",
		RealIP:       "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonSignMismatch, res.Reason)
}

func TestVerify_DifficultyNotMet(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	// "deadbeef" won't produce a 12-bit-zero hash, so difficulty check fails.
	payload := pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso", Difficulty: 12, Counter: "deadbeef",
	}
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + token + "&sign=" + sign,
		RealIP:       "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonDifficultyNotMet, res.Reason)
}

func TestVerify_Expired(t *testing.T) {
	svc, fc, _, mint := makeTestService(t, nil)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	token, sign := mint(payload)

	// Advance time past expiry.
	fc.Advance(2 * time.Hour)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + token + "&sign=" + sign,
		RealIP:       "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonExpired, res.Reason)
}

func TestVerify_DryRunRewritesDenyToAllow(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.DryRun = true
	svc, _, _, _ := makeTestService(t, cfg)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "", RealIP: "1.2.3.4",
	})
	assert.True(t, res.Allowed)
	assert.Equal(t, 200, res.HTTPStatus)
	assert.Equal(t, ReasonDryRunAllow, res.Reason)
	assert.Equal(t, ReasonMissingTokenOrSign, res.DryRunOriginalError)
}

func TestVerify_BypassAll(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.BypassAll = true
	svc, _, _, _ := makeTestService(t, cfg)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "", RealIP: "1.2.3.4",
	})
	assert.True(t, res.Allowed)
	assert.Equal(t, ReasonBypassAll, res.Reason)
}

func TestVerify_MissingHeaders(t *testing.T) {
	svc, _, _, _ := makeTestService(t, nil)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, 500, res.HTTPStatus)
	assert.Equal(t, ReasonMissingHeaders, res.Reason)
}

func TestVerify_ModeDisabled(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.Modes.Generic.Enabled = false
	svc, _, _, mint := makeTestService(t, cfg)
	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 4)
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + token + "&sign=" + sign,
		RealIP:       "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonModeDisabled, res.Reason)
}

func TestVerify_TTLTooLong(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.Modes.Generic.MaxTTLSeconds = 60
	svc, fc, _, mint := makeTestService(t, cfg)
	payload := pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
		Timestamp: fc.Now().Unix(),
		ExpiresAt: fc.Now().Unix() + 600, // 10 minutes > 60s
	}
	payload = findValidCounterForDifficulty(t, payload, 4)
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET",
		OriginalArgs: "token=" + token + "&sign=" + sign,
		RealIP:       "1.2.3.4",
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonTTLTooLong, res.Reason)
}

func TestStatusForReason(t *testing.T) {
	cases := map[string]int{
		ReasonNotProtected:       200,
		ReasonIPBoundValid:       200,
		ReasonGenericValid:       200,
		ReasonDryRunAllow:        200,
		ReasonBypassAll:          200,
		ReasonMissingHeaders:     500,
		ReasonStorageError:       500,
		ReasonInternalError:      500,
		ReasonRateLimited:        429,
		ReasonRiskTooMany:        429,
		ReasonMissingTokenOrSign: 403,
		ReasonSignMismatch:       403,
		ReasonIPMismatch:         403,
		ReasonUsedUp:             403,
	}
	for reason, want := range cases {
		assert.Equal(t, want, statusForReason(reason), "reason=%s", reason)
	}
}

func TestSameIP(t *testing.T) {
	assert.True(t, sameIP("1.2.3.4", "1.2.3.4"))
	assert.True(t, sameIP("::1", "::1"))
	assert.False(t, sameIP("1.2.3.4", "1.2.3.5"))
	assert.False(t, sameIP("", "1.2.3.4"))
	// IPv4-in-IPv6 representations should be equal.
	assert.True(t, sameIP("::ffff:1.2.3.4", "1.2.3.4"))
}
