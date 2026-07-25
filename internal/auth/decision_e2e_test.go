package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
)

func TestVerify_DecisionHeader_Populated(t *testing.T) {
	t.Run("not_protected", func(t *testing.T) {
		svc, _, _, _ := makeTestService(t, nil)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/index.html", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		assert.Equal(t, DecisionNotProtected, res.Decision)
	})

	t.Run("missing_token", func(t *testing.T) {
		svc, _, _, _ := makeTestService(t, nil)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		assert.Equal(t, DecisionDenied, res.Decision)
	})

	t.Run("bypass_all", func(t *testing.T) {
		cfg := makeBaseConfig()
		cfg.Pow.BypassAll = true
		svc, _, _, _ := makeTestService(t, cfg)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		assert.Equal(t, DecisionBypass, res.Decision)
	})

	t.Run("dry_run", func(t *testing.T) {
		cfg := makeBaseConfig()
		cfg.Pow.DryRun = true
		svc, _, _, _ := makeTestService(t, cfg)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		assert.Equal(t, DecisionDryRun, res.Decision)
	})

	t.Run("ip_bound_valid", func(t *testing.T) {
		svc, _, _, mint := makeTestService(t, nil)
		payload := findValidCounterForDifficulty(t, pow.TokenPayload{Mode: "ip_bound", Path: "/ubuntu.iso", IP: "1.2.3.4"}, 8)
		token, sign := mint(payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
			OriginalArgs: "token=" + token + "&sign=" + sign,
		})
		assert.Equal(t, DecisionVerified, res.Decision, "reason=%s", res.Reason)
	})

	t.Run("generic_valid", func(t *testing.T) {
		svc, _, _, mint := makeTestService(t, nil)
		payload := findValidCounterForDifficulty(t, pow.TokenPayload{Mode: "generic", Path: "/ubuntu.iso"}, 8)
		token, sign := mint(payload)
		res := svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4",
			OriginalArgs: "token=" + token + "&sign=" + sign,
		})
		assert.Equal(t, DecisionVerified, res.Decision)
	})
}

// TestVerify_IPHashing verifies that when logging.hash_ip is true, the
// service still produces correct decisions.
func TestVerify_IPHashing(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Logging.HashIP = true
	cfg.Logging.LogSalt = "test-salt"
	svc, _, _, _ := makeTestService(t, cfg)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/index.html", OriginalMethod: "GET", RealIP: "1.2.3.4",
	})
	assert.True(t, res.Allowed)
}
