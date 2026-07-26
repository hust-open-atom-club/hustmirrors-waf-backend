package storage

import (
	"context"
	"errors"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
)

// ActiveCounter is an optional capability: a UsageStore that can cheaply
// report how many usage records are currently live. memory and postgres
// implement it; drivers where the count would require a full keyspace
// scan (redis) deliberately do not.
type ActiveCounter interface {
	CountActive(ctx context.Context) (int64, error)
}

// InstrumentUsage wraps a UsageStore so every operation emits the
// storage_operations_total and storage_latency_seconds metrics under the
// given driver label. A nil container returns the store unchanged.
func InstrumentUsage(driver string, m *metrics.Container, next UsageStore) UsageStore {
	if m == nil || next == nil {
		return next
	}
	return &instrumentedUsage{driver: driver, m: m, next: next}
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

// CountActive forwards to the wrapped store when it supports counting,
// so the decorator does not hide the capability from callers.
func (s *instrumentedUsage) CountActive(ctx context.Context) (int64, error) {
	c, ok := s.next.(ActiveCounter)
	if !ok {
		return 0, ErrUnsupported
	}
	start := time.Now()
	n, err := c.CountActive(ctx)
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
