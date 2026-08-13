package risk

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPPendingBlocker_ManualBlockLifecycle(t *testing.T) {
	b := NewIPPendingBlocker(2, time.Minute)
	defer b.Close()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }

	result, err := b.Block("::ffff:192.0.2.10", BlockInput{TTL: time.Hour, Reason: "abuse", Actor: "ops"})
	require.NoError(t, err)
	assert.True(t, result.Changed)
	assert.Equal(t, "192.0.2.10", result.State.IP)
	assert.Equal(t, "manual", result.State.Source)
	assert.Equal(t, "abuse", result.State.Reason)
	assert.Equal(t, "ops", result.State.Actor)
	assert.True(t, b.ManuallyBlocked("192.0.2.10"))

	_, blocked := b.Enter("192.0.2.10")
	assert.True(t, blocked)

	now = now.Add(time.Hour)
	assert.False(t, b.ManuallyBlocked("192.0.2.10"))
	release, blocked := b.Enter("192.0.2.10")
	assert.False(t, blocked)
	release()
}

func TestIPPendingBlocker_UnblockKeepsAutomaticBlock(t *testing.T) {
	b := NewIPPendingBlocker(1, time.Hour)
	defer b.Close()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }

	release, blocked := b.Enter("192.0.2.20")
	require.False(t, blocked)
	_, blocked = b.Enter("192.0.2.20")
	require.True(t, blocked)
	release()

	_, err := b.Block("192.0.2.20", BlockInput{TTL: 2 * time.Hour, Reason: "manual review", Actor: "ops"})
	require.NoError(t, err)
	result, err := b.Unblock("192.0.2.20")
	require.NoError(t, err)
	assert.True(t, result.Changed)
	assert.True(t, result.State.Blocked)
	assert.Equal(t, "automatic", result.State.Source)
	assert.Equal(t, "pending_limit", result.State.Reason)
	assert.Equal(t, "system", result.State.Actor)
	assert.False(t, b.ManuallyBlocked("192.0.2.20"))
}

func TestIPPendingBlocker_ReblockDoesNotShortenTTL(t *testing.T) {
	b := NewIPPendingBlocker(1, time.Hour)
	defer b.Close()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }

	first, err := b.Block("192.0.2.30", BlockInput{TTL: 2 * time.Hour, Reason: "first", Actor: "ops"})
	require.NoError(t, err)
	now = now.Add(time.Minute)
	second, err := b.Block("192.0.2.30", BlockInput{TTL: 10 * time.Minute, Reason: "updated", Actor: "ops"})
	require.NoError(t, err)
	assert.True(t, second.Changed)
	assert.Equal(t, first.State.BlockedUntil, second.State.BlockedUntil)
	assert.Equal(t, "updated", second.State.Reason)
}

func TestCanonicalIPRejectsInvalidAndCIDR(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{name: "empty", ip: ""},
		{name: "invalid", ip: "not-an-ip"},
		{name: "cidr", ip: "192.0.2.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CanonicalIP(tt.ip)
			assert.ErrorIs(t, err, ErrInvalidBlockIP)
		})
	}
}

func TestIPPendingBlocker_ConcurrentManualOperations(t *testing.T) {
	b := NewIPPendingBlocker(8, time.Minute)
	defer b.Close()

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%3 == 0 {
				_, _ = b.Unblock("192.0.2.40")
				return
			}
			_, _ = b.Block("192.0.2.40", BlockInput{TTL: time.Hour, Reason: "concurrent", Actor: "ops"})
			release, _ := b.Enter("192.0.2.40")
			release()
		}(i)
	}
	wg.Wait()

	for _, item := range b.Snapshot() {
		assert.GreaterOrEqual(t, item.Pending, 0)
	}
}
