package storage

import (
	"context"
	"time"
)

// UsageStore records and atomically increments the usage counter for a
// generic-mode sign id. The only mutating operation is "consume one use,
// rejecting when at capacity"; callers cannot update arbitrary fields.
type UsageStore interface {
	Consume(ctx context.Context, in ConsumeInput) (ConsumeResult, error)

	// Get returns the current UsageRecord for the given id, or
	// ErrNotFound when no such record exists.
	Get(ctx context.Context, id string) (*UsageRecord, error)

	// CleanupExpired removes usage records whose ExpiresAt is strictly
	// less than beforeUnix. The returned int is the count of deleted
	// records (best-effort).
	CleanupExpired(ctx context.Context, beforeUnix int64) (int, error)

	Close() error
}

type ConsumeInput struct {
	ID        string
	Mode      string
	Path      string
	Sign      string
	TokenHash string
	ExpiresAt int64
	MaxUses   int
	IP        string
	UserAgent string
	// NowUnix is the server-side "now" timestamp, taken from clock.Clock.
	// Passed in explicitly so tests can drive time deterministically.
	NowUnix int64
	// GraceSeconds extends the Redis TTL beyond ExpiresAt to absorb
	// clock skew between client and server. When zero, a small default
	// (60s) is used by the redis implementation.
	GraceSeconds int
	// SkipConsume is set when the request method is HEAD and the mode
	// has count_head_request=false. The store should still return the
	// current count (and Allowed=true) without incrementing.
	SkipConsume bool
}

type ConsumeResult struct {
	Allowed bool
	Uses    int
	MaxUses int
	Reason  string
}

type UsageRecord struct {
	ID        string
	Mode      string
	Path      string
	Sign      string
	TokenHash string
	Uses      int
	MaxUses   int
	FirstIP   string
	LastIP    string
	UserAgent string
	ExpiresAt int64
	CreatedAt int64
	UpdatedAt int64
}

// CounterStore is a sliding-window counter API used by the risk engine.
// Keys are namespaced by `name`; within a name, `key` is typically a client
// IP or a path. The window is fixed and supplied per-call so different
// counters can have different windows.
type CounterStore interface {
	Incr(ctx context.Context, name, key string, window time.Duration) (int64, time.Duration, error)

	// Get returns the current value of the counter (name,key) within the
	// given window. The value is best-effort: a sliding-window
	// implementation may return an approximate count.
	Get(ctx context.Context, name, key string, window time.Duration) (int64, error)

	Reset(ctx context.Context, name, key string, window time.Duration) error

	Close() error
}
