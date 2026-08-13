package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/clock"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
)

func TestVerify_PendingBlockerRejectsConcurrentProtectedRequests(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	cfg.RiskControl.Pending.MaxPerIP = 1
	cfg.RiskControl.Pending.BlockTTL = time.Hour
	engine, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: risk.TargetRATELIMIT, LimitRate: "512k", Reason: "slow"},
		},
	})
	require.NoError(t, err)

	blocker := risk.NewIPPendingBlocker(1, time.Hour)
	defer blocker.Close()
	svc, _, _, _ := makeTestServiceWithPendingBlocker(t, cfg, engine, blocker)

	release, blocked := blocker.Enter("192.0.2.1")
	require.False(t, blocked)
	defer release()

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "192.0.2.1",
	})
	assert.Equal(t, ReasonIPPendingBlocked, res.Reason)
	assert.Equal(t, 429, res.HTTPStatus)
}

func TestVerify_PendingBlockerReleasesAfterRequest(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	cfg.RiskControl.Pending.MaxPerIP = 1
	engine, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: risk.TargetACCEPT, Reason: "ok"},
		},
	})
	require.NoError(t, err)

	blocker := risk.NewIPPendingBlocker(1, time.Hour)
	defer blocker.Close()
	svc, _, _, _ := makeTestServiceWithPendingBlocker(t, cfg, engine, blocker)

	first := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "192.0.2.1",
	})
	require.True(t, first.Allowed, "reason=%s", first.Reason)
	second := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "192.0.2.1",
	})
	assert.True(t, second.Allowed, "the defer release must return the slot")
}

func TestVerify_PendingBlockerDoesNotAffectUnprotectedPath(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	engine, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: risk.TargetACCEPT, Reason: "ok"},
		},
	})
	require.NoError(t, err)
	blocker := risk.NewIPPendingBlocker(1, time.Hour)
	defer blocker.Close()
	svc, _, _, _ := makeTestServiceWithPendingBlocker(t, cfg, engine, blocker)

	release, blocked := blocker.Enter("192.0.2.1")
	require.False(t, blocked)
	defer release()

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/index.html", OriginalMethod: "GET", RealIP: "192.0.2.1",
	})
	assert.True(t, res.Allowed, "an unprotected path must not request another pending slot")
	assert.NotEqual(t, ReasonIPPendingBlocked, res.Reason)
}

func TestVerify_PendingBlockerCanBeDisabled(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	off := false
	cfg.RiskControl.Pending.Enabled = &off
	engine, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: risk.TargetACCEPT, Reason: "ok"},
		},
	})
	require.NoError(t, err)
	blocker := risk.NewIPPendingBlocker(1, time.Hour)
	defer blocker.Close()
	svc, _, _, _ := makeTestServiceWithPendingBlocker(t, cfg, engine, blocker)

	release, blocked := blocker.Enter("192.0.2.1")
	require.False(t, blocked)
	defer release()

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "192.0.2.1",
	})
	assert.True(t, res.Allowed)
	assert.NotEqual(t, ReasonIPPendingBlocked, res.Reason)
}

func TestVerify_PendingBlockerDoesNotAffectBypassAll(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true
	cfg.Pow.BypassAll = true
	engine, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: risk.TargetACCEPT, Reason: "ok"},
		},
	})
	require.NoError(t, err)
	blocker := risk.NewIPPendingBlocker(1, time.Hour)
	defer blocker.Close()
	svc, _, _, _ := makeTestServiceWithPendingBlocker(t, cfg, engine, blocker)

	release, blocked := blocker.Enter("192.0.2.1")
	require.False(t, blocked)
	defer release()

	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "192.0.2.1",
	})
	assert.True(t, res.Allowed)
	assert.Equal(t, ReasonBypassAll, res.Reason)
}

func makeTestServiceWithPendingBlocker(t *testing.T, cfg *config.Config, engine *risk.Engine, blocker risk.PendingBlocker) (*Service, *clock.Fake, *memory.UsageStore, func(payload pow.TokenPayload) (token, sign string)) {
	t.Helper()
	return makeTestServiceWithEngineAndPending(t, cfg, engine, blocker)
}
