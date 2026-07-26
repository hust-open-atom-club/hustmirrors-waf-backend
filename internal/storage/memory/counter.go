package memory

import (
	"context"
	"sync"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

// CounterStore implements storage.CounterStore with fixed windows: the key
// embeds a bucket index of now/window, so counts don't carry across a
// rollover.
//
// Rolled-over buckets are unreachable but still resident, and the key space
// is attacker-influenced (usually client IP), so they're swept. Without
// that the map grows for the life of the process.
type CounterStore struct {
	mu      sync.Mutex
	buckets map[string]*counterBucket
	closed  bool

	// lastSweep throttles the scan so an Incr burst doesn't become a burst
	// of full map walks.
	lastSweep time.Time
}

type counterBucket struct {
	value     int64
	expiresAt time.Time
}

// Buckets are ~64 bytes, so a little residency beats frequent scans.
const sweepInterval = 30 * time.Second

func NewCounterStore() *CounterStore {
	return &CounterStore{buckets: make(map[string]*counterBucket)}
}

// sweepLocked drops expired buckets. The caller must hold s.mu.
func (s *CounterStore) sweepLocked(now time.Time) {
	if now.Sub(s.lastSweep) < sweepInterval {
		return
	}
	s.lastSweep = now
	for k, b := range s.buckets {
		if now.After(b.expiresAt) {
			delete(s.buckets, k)
		}
	}
}

func (s *CounterStore) Incr(_ context.Context, name, key string, window time.Duration) (int64, time.Duration, error) {
	if s.isClosed() {
		return 0, 0, storage.ErrClosed
	}
	if window <= 0 {
		return 0, 0, errInvalidWindow
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweepLocked(now)
	bucketKey := bucketKey(name, key, window, now)
	b, ok := s.buckets[bucketKey]
	if !ok || now.After(b.expiresAt) {
		b = &counterBucket{value: 0, expiresAt: now.Add(window)}
		s.buckets[bucketKey] = b
	}
	b.value++
	remaining := time.Until(b.expiresAt)
	if remaining < 0 {
		remaining = 0
	}
	return b.value, remaining, nil
}

func (s *CounterStore) Get(_ context.Context, name, key string, window time.Duration) (int64, error) {
	if s.isClosed() {
		return 0, storage.ErrClosed
	}
	if window <= 0 {
		return 0, errInvalidWindow
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	bucketKey := bucketKey(name, key, window, now)
	b, ok := s.buckets[bucketKey]
	if !ok || now.After(b.expiresAt) {
		return 0, nil
	}
	return b.value, nil
}

func (s *CounterStore) Reset(_ context.Context, name, key string, window time.Duration) error {
	if s.isClosed() {
		return storage.ErrClosed
	}
	if window <= 0 {
		return errInvalidWindow
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	bucketKey := bucketKey(name, key, window, now)
	delete(s.buckets, bucketKey)
	return nil
}

func (s *CounterStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.buckets = nil
	return nil
}

func (s *CounterStore) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// bucketKey returns the storage key for (name, key, window) at time t.
// The key includes the bucket start time so that a new bucket is used
// once the window rolls over.
func bucketKey(name, key string, window time.Duration, t time.Time) string {
	bucketStart := t.UnixNano() / int64(window) * int64(window)
	return name + "|" + key + "|" + itoa(bucketStart)
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
