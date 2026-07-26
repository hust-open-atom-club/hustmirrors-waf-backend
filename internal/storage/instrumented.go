package storage

import (
	"context"
	"errors"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
)

// ActiveCounter is optional: a UsageStore that can cheaply count live
// records. memory and postgres implement it; redis can't without a full
// keyspace scan.
type ActiveCounter interface {
	CountActive(ctx context.Context) (int64, error)
}

// InstrumentUsage wraps a UsageStore to emit storage_operations_total and
// storage_latency_seconds under the given driver label. Nil container
// returns the store unchanged.
//
// Returns a variant type when the wrapped store implements ActiveCounter,
// so the type assertion callers use reports the truth. A wrapper that
// always satisfied it would turn a static fact into a failed call on
// every cleanup tick.
func InstrumentUsage(driver string, m *metrics.Container, next UsageStore) UsageStore {
	if m == nil || next == nil {
		return next
	}
	base := &instrumentedUsage{driver: driver, m: m, next: next}
	if c, ok := next.(ActiveCounter); ok {
		return &instrumentedUsageCounter{instrumentedUsage: base, counter: c}
	}
	return base
}

type instrumentedUsage struct {
	driver string
	m      *metrics.Container
	next   UsageStore
}

func (s *instrumentedUsage) Consume(ctx context.Context, in ConsumeInput) (ConsumeResult, error) {
	start := time.Now()
	res, err := s.next.Consume(ctx, in)
	s.observe("consume", start, err)
	return res, err
}

func (s *instrumentedUsage) Get(ctx context.Context, id string) (*UsageRecord, error) {
	start := time.Now()
	rec, err := s.next.Get(ctx, id)
	// ErrNotFound is an expected outcome, not a storage failure.
	s.observe("get", start, ignoreNotFound(err))
	return rec, err
}

func (s *instrumentedUsage) CleanupExpired(ctx context.Context, beforeUnix int64) (int, error) {
	start := time.Now()
	n, err := s.next.CleanupExpired(ctx, beforeUnix)
	s.observe("cleanup_expired", start, err)
	return n, err
}

func (s *instrumentedUsage) Close() error { return s.next.Close() }

// instrumentedUsageCounter is the variant returned when the wrapped store
// supports ActiveCounter, so the capability survives the decoration.
type instrumentedUsageCounter struct {
	*instrumentedUsage
	counter ActiveCounter
}

func (s *instrumentedUsageCounter) CountActive(ctx context.Context) (int64, error) {
	start := time.Now()
	n, err := s.counter.CountActive(ctx)
	s.observe("count_active", start, err)
	return n, err
}

func (s *instrumentedUsage) observe(op string, start time.Time, err error) {
	s.m.StorageOperations.WithLabelValues(s.driver, op, outcome(err)).Inc()
	s.m.StorageLatencySeconds.WithLabelValues(s.driver, op).Observe(time.Since(start).Seconds())
}

// InstrumentCounter wraps a CounterStore with the same metrics as
// InstrumentUsage. A nil container returns the store unchanged.
func InstrumentCounter(driver string, m *metrics.Container, next CounterStore) CounterStore {
	if m == nil || next == nil {
		return next
	}
	return &instrumentedCounter{driver: driver, m: m, next: next}
}

type instrumentedCounter struct {
	driver string
	m      *metrics.Container
	next   CounterStore
}

func (s *instrumentedCounter) Incr(ctx context.Context, name, key string, window time.Duration) (int64, time.Duration, error) {
	start := time.Now()
	v, ttl, err := s.next.Incr(ctx, name, key, window)
	s.observe("counter_incr", start, err)
	return v, ttl, err
}

func (s *instrumentedCounter) Get(ctx context.Context, name, key string, window time.Duration) (int64, error) {
	start := time.Now()
	v, err := s.next.Get(ctx, name, key, window)
	s.observe("counter_get", start, err)
	return v, err
}

func (s *instrumentedCounter) Reset(ctx context.Context, name, key string, window time.Duration) error {
	start := time.Now()
	err := s.next.Reset(ctx, name, key, window)
	s.observe("counter_reset", start, err)
	return err
}

func (s *instrumentedCounter) Close() error { return s.next.Close() }

func (s *instrumentedCounter) observe(op string, start time.Time, err error) {
	s.m.StorageOperations.WithLabelValues(s.driver, op, outcome(err)).Inc()
	s.m.StorageLatencySeconds.WithLabelValues(s.driver, op).Observe(time.Since(start).Seconds())
}

func outcome(err error) string {
	if err != nil {
		return "err"
	}
	return "ok"
}

func ignoreNotFound(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
