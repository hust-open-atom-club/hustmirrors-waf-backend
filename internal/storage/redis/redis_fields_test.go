package redis

import (
	"context"
	"testing"
	"time"

	redistest "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

// TestUsageStore_HashFieldsComplete verifies that after first Consume the
// Redis Hash contains all expected fields.
func TestUsageStore_HashFieldsComplete(t *testing.T) {
	mr := redistest.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	s := NewUsageStore(client, "mirrors-waf-test")
	defer s.Close()
	now := int64(1700000000)
	in := storage.ConsumeInput{
		ID: "sid-full", Mode: "generic", Path: "/ubuntu.iso", Sign: "deadbeef",
		TokenHash: "tokhash", ExpiresAt: now + 600, MaxUses: 5,
		IP: "1.2.3.4", UserAgent: "curl/8", NowUnix: now, GraceSeconds: 30,
	}
	r, err := s.Consume(context.Background(), in)
	require.NoError(t, err)
	assert.True(t, r.Allowed)

	key := "mirrors-waf-test:pow:usage:sid-full"
	raw, err := client.HGetAll(context.Background(), key).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", raw["uses"])
	assert.Equal(t, "generic", raw["mode"])
	assert.Equal(t, "/ubuntu.iso", raw["path"])
	assert.Equal(t, "deadbeef", raw["sign"])
	assert.Equal(t, "tokhash", raw["token_hash"])
	assert.Equal(t, "5", raw["max_uses"])
	assert.Equal(t, "1.2.3.4", raw["first_ip"])
	assert.Equal(t, "1.2.3.4", raw["last_ip"])
	assert.Equal(t, "curl/8", raw["user_agent"])
	assert.Equal(t, "1700000600", raw["expires_at"])
	assert.Equal(t, "1700000000", raw["created_at"])
	assert.Equal(t, "1700000000", raw["updated_at"])

	// TTL should be (expires_at - now + grace) = 600 + 30 = 630.
	ttl, err := client.TTL(context.Background(), key).Result()
	require.NoError(t, err)
	assert.True(t, ttl > 600*time.Second, "TTL should include grace; got %v", ttl)
	assert.True(t, ttl <= 630*time.Second, "TTL should be ~630; got %v", ttl)

	rec, err := s.Get(context.Background(), "sid-full")
	require.NoError(t, err)
	assert.Equal(t, "generic", rec.Mode)
	assert.Equal(t, "/ubuntu.iso", rec.Path)
	assert.Equal(t, "deadbeef", rec.Sign)
	assert.Equal(t, "tokhash", rec.TokenHash)
	assert.Equal(t, 5, rec.MaxUses)
	assert.Equal(t, "1.2.3.4", rec.FirstIP)
	assert.Equal(t, "1.2.3.4", rec.LastIP)
	assert.Equal(t, "curl/8", rec.UserAgent)
	assert.Equal(t, int64(1700000600), rec.ExpiresAt)
}
