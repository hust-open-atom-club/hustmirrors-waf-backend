package risk

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPPendingBlocker_ConcurrentLimitAndRelease(t *testing.T) {
	b := NewIPPendingBlocker(3, time.Hour)
	defer b.Close()

	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	var releases []func()
	allowed := 0
	blocked := 0
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			release, isBlocked := b.Enter("192.0.2.1")
			mu.Lock()
			defer mu.Unlock()
			if isBlocked {
				blocked++
				return
			}
			allowed++
			releases = append(releases, release)
		}()
	}
	wg.Wait()

	assert.Equal(t, 3, allowed)
	assert.Equal(t, workers-3, blocked)
	for _, release := range releases {
		release()
		release()
	}

	_, isBlocked := b.Enter("192.0.2.1")
	assert.True(t, isBlocked, "overflow must start the temporary IP block")
}

func TestIPPendingBlocker_BlocksUntilTTL(t *testing.T) {
	b := NewIPPendingBlocker(1, time.Minute)
	defer b.Close()
	clock := time.Now()
	b.now = func() time.Time { return clock }

	release, blocked := b.Enter("192.0.2.1")
	assert.False(t, blocked)
	_, blocked = b.Enter("192.0.2.1")
	assert.True(t, blocked)
	release()

	_, blocked = b.Enter("192.0.2.1")
	assert.True(t, blocked)

	clock = clock.Add(time.Minute)
	release, blocked = b.Enter("192.0.2.1")
	assert.False(t, blocked)
	release()
}

func TestIPPendingBlocker_IsolatesIPsAndClose(t *testing.T) {
	b := NewIPPendingBlocker(1, time.Hour)

	release, blocked := b.Enter("192.0.2.1")
	require.False(t, blocked)
	_, blocked = b.Enter("192.0.2.2")
	assert.False(t, blocked)
	release()

	require.NoError(t, b.Close())
	require.NoError(t, b.Close())
	_, blocked = b.Enter("192.0.2.3")
	assert.True(t, blocked)
}

func TestIPPendingBlocker_NormalizesEquivalentIPs(t *testing.T) {
	b := NewIPPendingBlocker(1, time.Hour)
	defer b.Close()

	release, blocked := b.Enter("192.0.2.1")
	require.False(t, blocked)
	_, blocked = b.Enter("::ffff:192.0.2.1")
	assert.True(t, blocked, "IPv4-mapped IPv6 must share the IPv4 pending bucket")
	release()
}

func TestIPPendingBlocker_DoesNotTrackEmptyIP(t *testing.T) {
	b := NewIPPendingBlocker(1, time.Hour)
	defer b.Close()
	for range 10 {
		release, blocked := b.Enter("")
		assert.False(t, blocked)
		release()
	}
	assert.Empty(t, b.entries)
}
