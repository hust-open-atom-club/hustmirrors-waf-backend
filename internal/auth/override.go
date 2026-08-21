package auth

import (
	"sync"
	"time"
)

// OverrideKey identifies a runtime-overridable boolean switch.
type OverrideKey string

const (
	// OverrideBypassAll temporarily flips pow.bypass_all.
	OverrideBypassAll OverrideKey = "bypass_all"
	// OverrideDryRun temporarily flips pow.dry_run.
	OverrideDryRun OverrideKey = "dry_run"
)

// OverrideState is one active runtime override.
type OverrideState struct {
	Key       OverrideKey
	Value     bool
	Reason    string
	ExpiresAt time.Time
}

// overrideRegistry holds in-memory, process-local runtime overrides for the
// emergency switches. Overrides never touch the config file: a restart clears
// them, and each one expires on its own TTL so a forgotten bypass cannot
// outlive its window.
type overrideRegistry struct {
	mu        sync.Mutex
	overrides map[OverrideKey]OverrideState
}

func newOverrideRegistry() *overrideRegistry {
	return &overrideRegistry{overrides: make(map[OverrideKey]OverrideState)}
}

// Set installs (or replaces) an override for the given key.
func (r *overrideRegistry) Set(key OverrideKey, value bool, reason string, ttl time.Duration, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.overrides[key] = OverrideState{
		Key:       key,
		Value:     value,
		Reason:    reason,
		ExpiresAt: now.Add(ttl),
	}
}

// Clear removes the override for key, if present. Returns whether one existed.
func (r *overrideRegistry) Clear(key OverrideKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.overrides[key]; !ok {
		return false
	}
	delete(r.overrides, key)
	return true
}

// Lookup returns the active override for key, or nil when absent or expired.
// Expired entries are lazily removed.
func (r *overrideRegistry) Lookup(key OverrideKey, now time.Time) *OverrideState {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.overrides[key]
	if !ok {
		return nil
	}
	if !now.Before(state.ExpiresAt) {
		delete(r.overrides, key)
		return nil
	}
	s := state
	return &s
}

// Snapshot returns all active (unexpired) overrides in stable key order.
func (r *overrideRegistry) Snapshot(now time.Time) []OverrideState {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]OverrideState, 0, len(r.overrides))
	for key, state := range r.overrides {
		if !now.Before(state.ExpiresAt) {
			delete(r.overrides, key)
			continue
		}
		out = append(out, state)
	}
	// Two keys max today; keep insertion order stable for callers.
	if len(out) > 1 && out[0].Key > out[1].Key {
		out[0], out[1] = out[1], out[0]
	}
	return out
}
