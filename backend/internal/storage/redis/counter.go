package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

// CounterStore implements storage.CounterStore using Redis INCR with EXPIRE.
// The key includes the bucket start time so each window is a separate key.
type CounterStore struct {
	client    redis.Cmdable
	keyPrefix string
	closed    bool
}

func NewCounterStore(client redis.Cmdable, keyPrefix string) *CounterStore {
	if keyPrefix == "" {
		keyPrefix = "mirrors-waf"
	}
	return &CounterStore{client: client, keyPrefix: keyPrefix}
}

func (s *CounterStore) Incr(ctx context.Context, name, key string, window time.Duration) (int64, time.Duration, error) {
	if s.isClosed() {
		return 0, 0, storage.ErrClosed
	}
	if window <= 0 {
		return 0, 0, errInvalidWindow
	}
	now := time.Now()
	bucketStart := now.UnixNano() / int64(window) * int64(window)
	redisKey := s.counterKey(name, key, bucketStart)
	pipe := s.client.TxPipeline()
	incr := pipe.Incr(ctx, redisKey)
	pipe.Expire(ctx, redisKey, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, 0, fmt.Errorf("redis: incr: %w", err)
	}
	v, err := incr.Result()
	if err != nil {
		return 0, 0, fmt.Errorf("redis: incr result: %w", err)
	}
	bucketExpires := time.Unix(0, bucketStart).Add(window)
	remaining := time.Until(bucketExpires)
	if remaining < 0 {
		remaining = 0
	}
	return v, remaining, nil
}

func (s *CounterStore) Get(ctx context.Context, name, key string, window time.Duration) (int64, error) {
	if s.isClosed() {
		return 0, storage.ErrClosed
	}
	if window <= 0 {
		return 0, errInvalidWindow
	}
	now := time.Now()
	bucketStart := now.UnixNano() / int64(window) * int64(window)
	redisKey := s.counterKey(name, key, bucketStart)
	v, err := s.client.Get(ctx, redisKey).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("redis: get: %w", err)
	}
	return v, nil
}

func (s *CounterStore) Reset(ctx context.Context, name, key string, window time.Duration) error {
	if s.isClosed() {
		return storage.ErrClosed
	}
	if window <= 0 {
		return errInvalidWindow
	}
	now := time.Now()
	bucketStart := now.UnixNano() / int64(window) * int64(window)
	redisKey := s.counterKey(name, key, bucketStart)
	if _, err := s.client.Del(ctx, redisKey).Result(); err != nil {
		return fmt.Errorf("redis: reset: %w", err)
	}
	return nil
}

func (s *CounterStore) Close() error { s.closed = true; return nil }

func (s *CounterStore) isClosed() bool { return s.closed }

func (s *CounterStore) counterKey(name, key string, bucketStart int64) string {
	return s.keyPrefix + ":risk:counter:" + name + ":" + key + ":" + itoa(bucketStart)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

var errInvalidWindow = errors.New("redis: invalid counter window")

var _ storage.CounterStore = (*CounterStore)(nil)
