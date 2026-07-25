package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/matcher"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
)

func TestNew_RequiresUsageStoreWhenGenericEnabled(t *testing.T) {
	cfg := makeBaseConfig()
	m := matcher.NewComposite(matcher.NewExtensionMatcher(cfg.Protection.ProtectedExtensions), nil)
	_, err := New(Options{Config: cfg, Matcher: m})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UsageStore is required when generic mode is enabled")
}

func TestNew_AllowsNilUsageStoreWhenGenericDisabled(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.Pow.Modes.Generic.Enabled = false
	m := matcher.NewComposite(matcher.NewExtensionMatcher(cfg.Protection.ProtectedExtensions), nil)
	_, err := New(Options{Config: cfg, Matcher: m})
	require.NoError(t, err)
}

func TestNew_RequiresMatcherAndConfig(t *testing.T) {
	_, err := New(Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Config is required")

	cfg := makeBaseConfig()
	_, err = New(Options{Config: cfg})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Matcher is required")
}

func TestNew_AcceptsMemoryStore(t *testing.T) {
	cfg := makeBaseConfig()
	m := matcher.NewComposite(matcher.NewExtensionMatcher(cfg.Protection.ProtectedExtensions), nil)
	store := memory.NewUsageStore()
	svc, err := New(Options{Config: cfg, Matcher: m, UsageStore: store})
	require.NoError(t, err)
	assert.NotNil(t, svc)
}
