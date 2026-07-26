package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
)

// plainStore implements UsageStore but NOT ActiveCounter.
type plainStore struct{ getErr error }

func (p *plainStore) Consume(context.Context, ConsumeInput) (ConsumeResult, error) {
	return ConsumeResult{Allowed: true}, nil
}
func (p *plainStore) Get(context.Context, string) (*UsageRecord, error) {
	return nil, p.getErr
}
func (p *plainStore) CleanupExpired(context.Context, int64) (int, error) { return 0, nil }
func (p *plainStore) Close() error                                       { return nil }

// countingStore implements both UsageStore and ActiveCounter.
type countingStore struct {
	plainStore
	n int64
}

func (c *countingStore) CountActive(context.Context) (int64, error) { return c.n, nil }

// TestInstrumentUsage_DoesNotFakeActiveCounter pins that the decorator
// reports the wrapped store's real capabilities. Callers detect support
// with a type assertion; if the wrapper always satisfied ActiveCounter,
// drivers that cannot count (redis) would be probed on every cleanup tick
// and fail, instead of being skipped outright.
func TestInstrumentUsage_DoesNotFakeActiveCounter(t *testing.T) {
	m := metrics.New()

	wrapped := InstrumentUsage("redis", m, &plainStore{})
	_, ok := wrapped.(ActiveCounter)
	assert.False(t, ok, "a store without CountActive must not gain it through decoration")

	wrappedCounting := InstrumentUsage("memory", m, &countingStore{n: 7})
	c, ok := wrappedCounting.(ActiveCounter)
	require.True(t, ok, "a store with CountActive must keep it after decoration")
	n, err := c.CountActive(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(7), n)
}

// TestInstrumentUsage_NotFoundIsNotAnError ensures a routine cache miss is
// not recorded as a storage failure, which would make the error rate on
// the dashboard meaningless.
func TestInstrumentUsage_NotFoundIsNotAnError(t *testing.T) {
	m := metrics.New()
	s := InstrumentUsage("memory", m, &plainStore{getErr: ErrNotFound})

	_, err := s.Get(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound, "the sentinel must reach the caller unchanged")

	assert.Equal(t, float64(1), readCounter(t, m, "memory", "get", "ok"))
	assert.Equal(t, float64(0), readCounter(t, m, "memory", "get", "err"))
}

// TestInstrumentUsage_RealErrorIsCounted is the counterpart: a genuine
// failure must show up as err.
func TestInstrumentUsage_RealErrorIsCounted(t *testing.T) {
	m := metrics.New()
	s := InstrumentUsage("memory", m, &plainStore{getErr: errors.New("connection reset")})

	_, err := s.Get(context.Background(), "x")
	require.Error(t, err)

	assert.Equal(t, float64(1), readCounter(t, m, "memory", "get", "err"))
}

// TestInstrumentUsage_NilContainerIsPassThrough guards the wiring used by
// tests and by any future caller that builds a store without metrics.
func TestInstrumentUsage_NilContainerIsPassThrough(t *testing.T) {
	inner := &plainStore{}
	assert.Same(t, UsageStore(inner), InstrumentUsage("memory", nil, inner))
	assert.Nil(t, InstrumentUsage("memory", metrics.New(), nil))
}

func readCounter(t *testing.T, m *metrics.Container, driver, op, outcome string) float64 {
	t.Helper()
	c, err := m.StorageOperations.GetMetricWithLabelValues(driver, op, outcome)
	require.NoError(t, err)
	return testutil.ToFloat64(c)
}
