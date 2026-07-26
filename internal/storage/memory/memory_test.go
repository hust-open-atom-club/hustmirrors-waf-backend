package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

func newInput(id string, maxUses int, ip string, now int64) storage.ConsumeInput {
	return storage.ConsumeInput{
		ID:        id,
		Mode:      "generic",
		Path:      "/x.iso",
		Sign:      "deadbeef",
		TokenHash: "tok",
		ExpiresAt: now + 600,
		MaxUses:   maxUses,
		IP:        ip,
		UserAgent: "ua",
		NowUnix:   now,
	}
}

func TestUsageStore_Consume_Basic(t *testing.T) {
	s := NewUsageStore()
	defer s.Close()

	now := int64(1700000000)
	r, err := s.Consume(context.Background(), newInput("id1", 3, "1.1.1.1", now))
	require.NoError(t, err)
	assert.True(t, r.Allowed)
	assert.Equal(t, 1, r.Uses)
	assert.Equal(t, 3, r.MaxUses)

	r, err = s.Consume(context.Background(), newInput("id1", 3, "2.2.2.2", now+10))
	require.NoError(t, err)
	assert.True(t, r.Allowed)
	assert.Equal(t, 2, r.Uses)
}

func TestUsageStore_Consume_UsedUp(t *testing.T) {
	s := NewUsageStore()
	defer s.Close()
	now := int64(1700000000)
	_, _ = s.Consume(context.Background(), newInput("id1", 2, "1.1.1.1", now))
	_, _ = s.Consume(context.Background(), newInput("id1", 2, "1.1.1.1", now+1))
	r, err := s.Consume(context.Background(), newInput("id1", 2, "1.1.1.1", now+2))
	require.NoError(t, err)
	assert.False(t, r.Allowed)
	assert.Equal(t, 2, r.Uses)
	assert.Equal(t, "used_up", r.Reason)
}

func TestUsageStore_Consume_SkipConsumeHeadRequest(t *testing.T) {
	s := NewUsageStore()
	defer s.Close()
	now := int64(1700000000)
	in := newInput("id1", 3, "1.1.1.1", now)
	in.SkipConsume = true
	r, err := s.Consume(context.Background(), in)
	require.NoError(t, err)
	assert.True(t, r.Allowed)
	assert.Equal(t, 0, r.Uses, "skip should not increment uses")

	// subsequent consume should still be 1
	r, err = s.Consume(context.Background(), newInput("id1", 3, "1.1.1.1", now+1))
	require.NoError(t, err)
	assert.Equal(t, 1, r.Uses)
}

func TestUsageStore_Get_NotFound(t *testing.T) {
	s := NewUsageStore()
	defer s.Close()
	_, err := s.Get(context.Background(), "nope")
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestUsageStore_Get_ReturnsCopy(t *testing.T) {
	s := NewUsageStore()
	defer s.Close()
	now := int64(1700000000)
	_, _ = s.Consume(context.Background(), newInput("id1", 3, "1.1.1.1", now))
	rec, err := s.Get(context.Background(), "id1")
	require.NoError(t, err)
	assert.Equal(t, 1, rec.Uses)

	// Mutating the returned record must not affect the store.
	rec.Uses = 999
	rec2, err := s.Get(context.Background(), "id1")
	require.NoError(t, err)
	assert.Equal(t, 1, rec2.Uses)
}

func TestUsageStore_CleanupExpired(t *testing.T) {
	s := NewUsageStore()
	defer s.Close()
	now := int64(1700000000)
	in1 := newInput("id1", 3, "1.1.1.1", now)
	in1.ExpiresAt = now + 10
	in2 := newInput("id2", 3, "1.1.1.1", now)
	in2.ExpiresAt = now - 5
	_, _ = s.Consume(context.Background(), in1)
	_, _ = s.Consume(context.Background(), in2)

	removed, err := s.CleanupExpired(context.Background(), now)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	_, err = s.Get(context.Background(), "id2")
	require.ErrorIs(t, err, storage.ErrNotFound)

	_, err = s.Get(context.Background(), "id1")
	require.NoError(t, err)
}

func TestUsageStore_ConcurrentConsumeRespectsMaxUses(t *testing.T) {
	s := NewUsageStore()
	defer s.Close()
	const workers = 20
	const maxUses = 3

	var wg sync.WaitGroup
	wg.Add(workers)
	allowed := make([]bool, workers)
	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer wg.Done()
			r, err := s.Consume(context.Background(), newInput("shared", maxUses, "1.1.1.1", 1700000000))
			if err == nil {
				allowed[i] = r.Allowed
			}
		}()
	}
	wg.Wait()

	count := 0
	for _, a := range allowed {
		if a {
			count++
		}
	}
	assert.Equal(t, maxUses, count, "only %d consumes should be allowed", maxUses)

	rec, err := s.Get(context.Background(), "shared")
	require.NoError(t, err)
	assert.Equal(t, maxUses, rec.Uses)
}

func TestUsageStore_Close_ErrorsAfterClose(t *testing.T) {
	s := NewUsageStore()
	require.NoError(t, s.Close())
	_, err := s.Consume(context.Background(), newInput("x", 1, "1.1.1.1", 1))
	require.ErrorIs(t, err, storage.ErrClosed)
}

func TestCounterStore_Basic(t *testing.T) {
	s := NewCounterStore()
	defer s.Close()
	ctx := context.Background()
	v, _, err := s.Incr(ctx, "ip_protected_10m", "1.2.3.4", 10*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)
	v, _, err = s.Incr(ctx, "ip_protected_10m", "1.2.3.4", 10*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(2), v)
	got, err := s.Get(ctx, "ip_protected_10m", "1.2.3.4", 10*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got)
}

func TestCounterStore_DifferentNamespaces(t *testing.T) {
	s := NewCounterStore()
	defer s.Close()
	ctx := context.Background()
	_, _, _ = s.Incr(ctx, "a", "1.2.3.4", 10*time.Minute)
	v, _, _ := s.Incr(ctx, "b", "1.2.3.4", 10*time.Minute)
	assert.Equal(t, int64(1), v)
}

func TestCounterStore_Reset(t *testing.T) {
	s := NewCounterStore()
	defer s.Close()
	ctx := context.Background()
	_, _, _ = s.Incr(ctx, "a", "1.2.3.4", 10*time.Minute)
	_, _, _ = s.Incr(ctx, "a", "1.2.3.4", 10*time.Minute)
	require.NoError(t, s.Reset(ctx, "a", "1.2.3.4", 10*time.Minute))
	v, _ := s.Get(ctx, "a", "1.2.3.4", 10*time.Minute)
	assert.Equal(t, int64(0), v)
}

func TestCounterStore_InvalidWindow(t *testing.T) {
	s := NewCounterStore()
	defer s.Close()
	_, _, err := s.Incr(context.Background(), "a", "k", 0)
	require.True(t, errors.Is(err, errInvalidWindow))
}

func TestCounterStore_CloseErrors(t *testing.T) {
	s := NewCounterStore()
	require.NoError(t, s.Close())
	_, _, err := s.Incr(context.Background(), "a", "k", time.Minute)
	require.ErrorIs(t, err, storage.ErrClosed)
}

// TestCounterStore_ExpiredBucketsAreReclaimed guards against unbounded
// growth. The bucket key embeds a window index, so every rollover mints a
// fresh key while the previous one becomes unreachable. Nothing used to
// remove them, and because counters are normally keyed by client IP the
// key space is attacker-influenced: the map grew until the process died.
func TestCounterStore_ExpiredBucketsAreReclaimed(t *testing.T) {
	s := NewCounterStore()
	defer s.Close()
	ctx := context.Background()
	const window = time.Millisecond

	for i := 0; i < 200; i++ {
		// The sweep is time-throttled; reset the clock on it so the test
		// exercises reclamation without sleeping for the real interval.
		s.mu.Lock()
		s.lastSweep = time.Now().Add(-time.Hour)
		s.mu.Unlock()

		_, _, err := s.Incr(ctx, "req", "1.2.3.4", window)
		require.NoError(t, err)
		time.Sleep(window)
	}

	s.mu.Lock()
	n := len(s.buckets)
	s.mu.Unlock()
	assert.LessOrEqual(t, n, 5,
		"expired buckets must be reclaimed; got %d live buckets for one key", n)
}

// TestCounterStore_SweepPreservesLiveCounts ensures reclamation never
// discards a bucket that is still inside its window - that would silently
// reset a rate limit mid-flight.
func TestCounterStore_SweepPreservesLiveCounts(t *testing.T) {
	s := NewCounterStore()
	defer s.Close()
	ctx := context.Background()
	const window = time.Hour

	for i := 0; i < 3; i++ {
		s.mu.Lock()
		s.lastSweep = time.Now().Add(-time.Hour)
		s.mu.Unlock()
		_, _, err := s.Incr(ctx, "req", "1.2.3.4", window)
		require.NoError(t, err)
	}

	got, err := s.Get(ctx, "req", "1.2.3.4", window)
	require.NoError(t, err)
	assert.Equal(t, int64(3), got, "sweeping must not drop a bucket still in window")
}
