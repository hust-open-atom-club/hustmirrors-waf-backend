package admin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/auth"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
)

// stubOverrideSource is a minimal OverrideSource backed by a real registry
// with a controllable clock via direct state injection.
type stubOverrideSource struct {
	states []auth.OverrideState
}

func (s *stubOverrideSource) SetOverride(key auth.OverrideKey, value bool, reason string, ttl time.Duration) {
	s.states = append(s.states, auth.OverrideState{Key: key, Value: value, Reason: reason, ExpiresAt: time.Now().Add(ttl)})
}

func (s *stubOverrideSource) ClearOverride(key auth.OverrideKey) bool {
	for i, st := range s.states {
		if st.Key == key {
			s.states = append(s.states[:i], s.states[i+1:]...)
			return true
		}
	}
	return false
}

func (s *stubOverrideSource) OverrideSnapshot() []auth.OverrideState {
	out := make([]auth.OverrideState, 0, len(s.states))
	for _, st := range s.states {
		if time.Now().Before(st.ExpiresAt) {
			out = append(out, st)
		}
	}
	return out
}

func newRuntimeTestService(t *testing.T) *Service {
	t.Helper()
	cfg := &config.Config{}
	cfg.Admin.Enabled = true
	cfg.Admin.Auth.Type = "token"
	cfg.Admin.MutationsEnabled = true
	svc, err := New(Options{Config: cfg, Overrides: &stubOverrideSource{}})
	require.NoError(t, err)
	return svc
}

func TestRuntimeStatus_ReflectsConfig(t *testing.T) {
	svc := newRuntimeTestService(t)
	resp, err := svc.RuntimeStatus(t.Context(), RuntimeStatusRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Switches, 2)
	assert.Equal(t, "bypass_all", resp.Switches[0].Key)
	assert.False(t, resp.Switches[0].ConfigValue)
	assert.False(t, resp.Switches[0].Overridden)
	assert.Empty(t, resp.Overrides)
}

func TestRuntimeOverrideSet_Validation(t *testing.T) {
	svc := newRuntimeTestService(t)

	_, err := svc.RuntimeOverrideSet(t.Context(), RuntimeOverrideSetRequest{Key: "unknown", Value: true, Reason: "r", TTLSeconds: 60})
	assert.Error(t, err, "unknown key must be rejected")

	_, err = svc.RuntimeOverrideSet(t.Context(), RuntimeOverrideSetRequest{Key: "bypass_all", Value: true, Reason: "", TTLSeconds: 60})
	assert.Error(t, err, "missing reason must be rejected")

	_, err = svc.RuntimeOverrideSet(t.Context(), RuntimeOverrideSetRequest{Key: "bypass_all", Value: true, Reason: "r", TTLSeconds: 0})
	assert.Error(t, err, "zero ttl must be rejected")

	_, err = svc.RuntimeOverrideSet(t.Context(), RuntimeOverrideSetRequest{Key: "bypass_all", Value: true, Reason: "r", TTLSeconds: int(MaxOverrideTTL.Seconds()) + 1})
	assert.Error(t, err, "ttl beyond cap must be rejected")
}

func TestRuntimeOverrideSet_AndClear(t *testing.T) {
	svc := newRuntimeTestService(t)
	src := svc.overrides.(*stubOverrideSource)

	resp, err := svc.RuntimeOverrideSet(t.Context(), RuntimeOverrideSetRequest{Key: "dry_run", Value: true, Reason: "staging drill", TTLSeconds: 120})
	require.NoError(t, err)
	require.Len(t, resp.Overrides, 1)
	assert.Equal(t, "dry_run", resp.Overrides[0].Key)
	assert.True(t, resp.Overrides[0].Value)

	for _, sw := range resp.Switches {
		if sw.Key == "dry_run" {
			assert.True(t, sw.Overridden)
			assert.True(t, sw.ActiveValue)
			assert.Equal(t, "staging drill", sw.Reason)
		}
	}

	resp, err = svc.RuntimeOverrideClear(t.Context(), RuntimeOverrideClearRequest{Key: "dry_run"})
	require.NoError(t, err)
	assert.Empty(t, resp.Overrides)
	assert.False(t, src.hasOverride("dry_run"))
}

func (s *stubOverrideSource) hasOverride(key auth.OverrideKey) bool {
	for _, st := range s.states {
		if st.Key == key {
			return true
		}
	}
	return false
}

func TestRuntimeOverride_MutationsDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.Auth.Type = "token"
	cfg.Admin.MutationsEnabled = false
	svc, err := New(Options{Config: cfg, Overrides: &stubOverrideSource{}})
	require.NoError(t, err)

	_, err = svc.RuntimeOverrideSet(t.Context(), RuntimeOverrideSetRequest{Key: "bypass_all", Value: true, Reason: "r", TTLSeconds: 60})
	assert.Error(t, err)
}
