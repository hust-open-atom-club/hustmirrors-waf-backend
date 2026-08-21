package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

)

func TestOverrideRegistry_TTLExpiry(t *testing.T) {
	r := newOverrideRegistry()
	now := time.Now()
	r.Set(OverrideBypassAll, true, "incident", 10*time.Minute, now)

	st := r.Lookup(OverrideBypassAll, now.Add(5*time.Minute))
	require.NotNil(t, st)
	assert.True(t, st.Value)

	// After expiry the entry is gone.
	assert.Nil(t, r.Lookup(OverrideBypassAll, now.Add(11*time.Minute)))
	// And a second lookup (post lazy-delete) still finds nothing.
	assert.Nil(t, r.Lookup(OverrideBypassAll, now.Add(12*time.Minute)))
}

func TestOverrideRegistry_Clear(t *testing.T) {
	r := newOverrideRegistry()
	now := time.Now()
	r.Set(OverrideDryRun, true, "drill", time.Hour, now)
	assert.True(t, r.Clear(OverrideDryRun))
	assert.False(t, r.Clear(OverrideDryRun), "clearing again is a no-op")
	assert.Nil(t, r.Lookup(OverrideDryRun, now))
}

func TestOverrideRegistry_SnapshotFiltersExpired(t *testing.T) {
	r := newOverrideRegistry()
	now := time.Now()
	r.Set(OverrideBypassAll, true, "a", time.Hour, now)
	r.Set(OverrideDryRun, false, "b", time.Minute, now)

	got := r.Snapshot(now.Add(30 * time.Second))
	assert.Len(t, got, 2, "both still active")

	got = r.Snapshot(now.Add(2 * time.Minute))
	assert.Len(t, got, 1, "expired dry_run filtered out")
	assert.Equal(t, OverrideBypassAll, got[0].Key)
}

func TestService_BypassAllOverrideEffective(t *testing.T) {
	svc, fc, _, _ := makeTestService(t, nil)
	assert.False(t, svc.bypassAllEffective(), "config default is off")

	svc.SetOverride(OverrideBypassAll, true, "upstream outage", 5*time.Minute)
	assert.True(t, svc.bypassAllEffective(), "override must win while active")

	// Verify honours the override: any request is allowed with reason bypass_all.
	res := svc.Verify(t.Context(), AuthRequest{
		OriginalURI:    "/whatever.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "",
		RealIP:         "203.0.113.5",
	})
	assert.True(t, res.Allowed)
	assert.Equal(t, ReasonBypassAll, res.Reason)

	// After TTL the override self-clears and the config value returns.
	// The test service uses a fake clock, so move it beyond the five-minute TTL.
	fc.Advance(10 * time.Minute)
	assert.False(t, svc.bypassAllEffective(), "expired override must fall back to config")
}

func TestService_DryRunOverrideEffective(t *testing.T) {
	svc, _, _, _ := makeTestService(t, nil)
	assert.False(t, svc.dryRunEffective())

	svc.SetOverride(OverrideDryRun, true, "staging", time.Hour)
	assert.True(t, svc.dryRunEffective())
}
