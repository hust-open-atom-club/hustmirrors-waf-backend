package redis

import (
	"context"
	"sync"
	"testing"
	"time"

	redistest "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

func startMiniRedis(t *testing.T) (redis.Cmdable, func()) {
	t.Helper()
	mr := redistest.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return client, func() { _ = client.Close() }
}

func TestUsageStore_Consume_FirstUse(t *testing.T) {
	client, stop := startMiniRedis(t)
	defer stop()

	s := NewUsageStore(client, "mirrors-waf-test")
	defer s.Close()
	now := int64(1700000000)
	in := storage.ConsumeInput{
		ID: "sid1", Mode: "generic", Path: "/x.iso", Sign: "s",
		TokenHash: "tok", ExpiresAt: now + 600, MaxUses: 3,
		IP: "1.2.3.4", UserAgent: "ua", NowUnix: now,
	}
	r, err := s.Consume(context.Background(), in)
	require.NoError(t, err)
	assert.True(t, r.Allowed)
	assert.Equal(t, 1, r.Uses)

	r, err = s.Consume(context.Background(), in)
	require.NoError(t, err)
	assert.True(t, r.Allowed)
	assert.Equal(t, 2, r.Uses)
}

func TestUsageStore_Consume_UsedUp(t *testing.T) {
	client, stop := startMiniRedis(t)
	defer stop()
	s := NewUsageStore(client, "mirrors-waf-test")
	defer s.Close()
	now := int64(1700000000)
	in := storage.ConsumeInput{ID: "sid2", Mode: "generic", Path: "/x.iso", Sign: "s",
		TokenHash: "tok", ExpiresAt: now + 600, MaxUses: 2, IP: "1.2.3.4", UserAgent: "ua", NowUnix: now}
	_, _ = s.Consume(context.Background(), in)
	_, _ = s.Consume(context.Background(), in)
	r, err := s.Consume(context.Background(), in)
	require.NoError(t, err)
	assert.False(t, r.Allowed)
	assert.Equal(t, 2, r.Uses)
}

func TestUsageStore_Consume_SkipConsumeHead(t *testing.T) {
	client, stop := startMiniRedis(t)
	defer stop()
	s := NewUsageStore(client, "mirrors-waf-test")
	defer s.Close()
	now := int64(1700000000)
	in := storage.ConsumeInput{ID: "sid3", Mode: "generic", Path: "/x.iso", Sign: "s",
		TokenHash: "tok", ExpiresAt: now + 600, MaxUses: 3, IP: "1.2.3.4", UserAgent: "ua", NowUnix: now}
	in.SkipConsume = true
	r, err := s.Consume(context.Background(), in)
	require.NoError(t, err)
	assert.True(t, r.Allowed)
	assert.Equal(t, 0, r.Uses)

	// Real consume increments to 1
	in.SkipConsume = false
	r, err = s.Consume(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, 1, r.Uses)
}

func TestUsageStore_Get(t *testing.T) {
	client, stop := startMiniRedis(t)
	defer stop()
	s := NewUsageStore(client, "mirrors-waf-test")
	defer s.Close()
	now := int64(1700000000)
	in := storage.ConsumeInput{ID: "sid4", Mode: "generic", Path: "/x.iso", Sign: "s",
		TokenHash: "tok", ExpiresAt: now + 600, MaxUses: 3, IP: "1.2.3.4", UserAgent: "ua", NowUnix: now}
	_, err := s.Consume(context.Background(), in)
	require.NoError(t, err)

	rec, err := s.Get(context.Background(), "sid4")
	require.NoError(t, err)
	assert.Equal(t, 1, rec.Uses)
	assert.Equal(t, "1.2.3.4", rec.FirstIP)
	assert.Equal(t, "1.2.3.4", rec.LastIP)

	_, err = s.Get(context.Background(), "missing")
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestCounterStore_Basic(t *testing.T) {
	client, stop := startMiniRedis(t)
	defer stop()
	s := NewCounterStore(client, "mirrors-waf-test")
	defer s.Close()
	ctx := context.Background()
	v, _, err := s.Incr(ctx, "c1", "1.2.3.4", 10*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)
	v, _, err = s.Incr(ctx, "c1", "1.2.3.4", 10*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(2), v)
	got, err := s.Get(ctx, "c1", "1.2.3.4", 10*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got)

	require.NoError(t, s.Reset(ctx, "c1", "1.2.3.4", 10*time.Minute))
	got, _ = s.Get(ctx, "c1", "1.2.3.4", 10*time.Minute)
	assert.Equal(t, int64(0), got)
}

func TestUsageStore_AlreadyExpired(t *testing.T) {
	client, stop := startMiniRedis(t)
	defer stop()
	s := NewUsageStore(client, "mirrors-waf-test")
	defer s.Close()
	now := int64(1700000000)
	in := storage.ConsumeInput{ID: "sid5", ExpiresAt: now - 100, MaxUses: 3, NowUnix: now}
	r, err := s.Consume(context.Background(), in)
	require.NoError(t, err)
	assert.False(t, r.Allowed)
	assert.Equal(t, "expired", r.Reason)
}

// TestStores_ConcurrentCloseIsSafe exercises Close racing against in-flight
// requests, which is exactly what happens on shutdown.
//
// closed used to be a plain bool written by Close and read by every
// operation, i.e. a data race. The memory store had always guarded it with
// a mutex; these two had not.
//
// Note: the race detector needs CGO, which is unavailable on this machine,
// so this test verifies observable behaviour (no panic, ErrClosed after
// close) rather than proving the absence of a race.
func TestStores_ConcurrentCloseIsSafe(t *testing.T) {
	client, stop := startMiniRedis(t)
	defer stop()

	usage := NewUsageStore(client, "concurrency-test")
	counter := NewCounterStore(client, "concurrency-test")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _, _ = counter.Incr(context.Background(), "req", "1.2.3.4", time.Minute)
		}()
		go func() {
			defer wg.Done()
			_, _ = usage.Get(context.Background(), "some-id")
		}()
	}
	wg.Add(2)
	go func() { defer wg.Done(); _ = usage.Close() }()
	go func() { defer wg.Done(); _ = counter.Close() }()
	wg.Wait()

	// After Close both stores must consistently report ErrClosed.
	_, err := usage.Get(context.Background(), "x")
	require.ErrorIs(t, err, storage.ErrClosed)
	_, _, err = counter.Incr(context.Background(), "req", "1.2.3.4", time.Minute)
	require.ErrorIs(t, err, storage.ErrClosed)
}
