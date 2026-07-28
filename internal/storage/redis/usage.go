package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

// closed is mutex-guarded for the same reason as in CounterStore: Close
// runs on the shutdown goroutine while requests are still reading it.
type UsageStore struct {
	client    redis.Cmdable
	keyPrefix string

	mu     sync.Mutex
	closed bool
}

func NewUsageStore(client redis.Cmdable, keyPrefix string) *UsageStore {
	if keyPrefix == "" {
		keyPrefix = "mirrors-waf"
	}
	return &UsageStore{client: client, keyPrefix: keyPrefix}
}

func (s *UsageStore) Consume(ctx context.Context, in storage.ConsumeInput) (storage.ConsumeResult, error) {
	if s.isClosed() {
		return storage.ConsumeResult{}, storage.ErrClosed
	}
	now := in.NowUnix
	if now == 0 {
		now = time.Now().Unix()
	}
	grace := in.GraceSeconds
	if grace <= 0 {
		grace = 60
	}
	ttl := in.ExpiresAt - now + int64(grace)
	if in.ExpiresAt-now <= 0 {
		return storage.ConsumeResult{Allowed: false, Uses: 0, MaxUses: in.MaxUses, Reason: "expired"}, nil
	}
	key := s.usageKey(in.ID)

	if in.SkipConsume {
		v, err := s.client.HGet(ctx, key, "uses").Int64()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return storage.ConsumeResult{Allowed: true, Uses: 0, MaxUses: in.MaxUses, Reason: "ok_head_first"}, nil
			}
			return storage.ConsumeResult{}, fmt.Errorf("redis: head consume: %w", err)
		}
		allowed := int(v) < in.MaxUses
		reason := "ok_head"
		if !allowed {
			reason = "used_up_head"
		}
		return storage.ConsumeResult{Allowed: allowed, Uses: int(v), MaxUses: in.MaxUses, Reason: reason}, nil
	}

	res, err := consumeUsage.Run(ctx, s.client, []string{key},
		in.MaxUses, ttl, now, in.IP, in.UserAgent,
		in.Mode, in.Path, in.Sign, in.TokenHash, in.ExpiresAt,
	).Slice()
	if err != nil {
		return storage.ConsumeResult{}, fmt.Errorf("redis: consume lua: %w", err)
	}
	if len(res) < 2 {
		return storage.ConsumeResult{}, fmt.Errorf("redis: consume lua: unexpected result shape %v", res)
	}
	allowed, _ := res[0].(int64)
	uses, _ := res[1].(int64)
	cr := storage.ConsumeResult{
		Allowed: allowed == 1,
		Uses:    int(uses),
		MaxUses: in.MaxUses,
		Reason:  "ok",
	}
	if !cr.Allowed {
		cr.Reason = "used_up"
	}
	return cr, nil
}

func (s *UsageStore) Get(ctx context.Context, id string) (*storage.UsageRecord, error) {
	if s.isClosed() {
		return nil, storage.ErrClosed
	}
	key := s.usageKey(id)
	raw, err := s.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: get: %w", err)
	}
	if len(raw) == 0 {
		return nil, storage.ErrNotFound
	}
	r := &storage.UsageRecord{ID: id}
	r.Mode = raw["mode"]
	r.Path = raw["path"]
	r.Sign = raw["sign"]
	r.TokenHash = raw["token_hash"]
	r.FirstIP = raw["first_ip"]
	r.LastIP = raw["last_ip"]
	r.UserAgent = raw["user_agent"]
	if v, err := strconv.Atoi(raw["uses"]); err == nil {
		r.Uses = v
	}
	if v, err := strconv.Atoi(raw["max_uses"]); err == nil {
		r.MaxUses = v
	}
	if v, err := strconv.ParseInt(raw["expires_at"], 10, 64); err == nil {
		r.ExpiresAt = v
	}
	if v, err := strconv.ParseInt(raw["created_at"], 10, 64); err == nil {
		r.CreatedAt = v
	}
	if v, err := strconv.ParseInt(raw["updated_at"], 10, 64); err == nil {
		r.UpdatedAt = v
	}
	return r, nil
}

// CleanupExpired is intentionally a no-op.
//
// Every usage key is written with a TTL of (expires_at - now + grace) by the
// consume Lua script, so Redis evicts records on its own. Scanning the
// keyspace to delete them early would cost an O(N) SCAN on a hot instance to
// reclaim memory that is already scheduled for release.
//
// Returning (0, nil) is therefore accurate: this driver removed nothing
// because there was nothing for it to remove.
func (s *UsageStore) CleanupExpired(_ context.Context, _ int64) (int, error) {
	return 0, nil
}

func (s *UsageStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *UsageStore) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *UsageStore) usageKey(id string) string {
	return s.keyPrefix + ":pow:usage:" + id
}

// Note: this driver deliberately does NOT implement storage.ActiveCounter.
// Counting live usage records would require a full SCAN of the keyspace on
// every cleanup tick. The storage_active_signatures gauge is therefore not
// populated when storage.driver=redis.
var _ storage.UsageStore = (*UsageStore)(nil)
