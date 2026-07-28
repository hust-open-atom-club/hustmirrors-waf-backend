package risk

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
)

// brokenCounterStore fails every read, as an unreachable backend would.
type brokenCounterStore struct{}

func (brokenCounterStore) Incr(context.Context, string, string, time.Duration) (int64, time.Duration, error) {
	return 0, 0, errors.New("connection refused")
}
func (brokenCounterStore) Get(context.Context, string, string, time.Duration) (int64, error) {
	return 0, errors.New("connection refused")
}
func (brokenCounterStore) Reset(context.Context, string, string, time.Duration) error {
	return errors.New("connection refused")
}
func (brokenCounterStore) Close() error { return nil }

// TestCounterResolver_LogsReadFailure pins the observability of a fail-open
// path. A counter read error resolves to 0, so a rule such as
// "counter >= N -> REJECT" stops rejecting the moment the backend is
// unreachable. Returning 0 is deliberate - failing closed would drop all
// traffic on a transient hiccup - but it must not be silent.
func TestCounterResolver_LogsReadFailure(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := logging.NewFromZap(zap.New(core))

	defs := map[string]config.CounterConfig{
		"req_per_ip": {Key: "ip", Window: time.Minute},
	}
	reg := NewCounterRegistry(defs, brokenCounterStore{}).WithLogger(logger)
	resolver := reg.LookupResolver(context.Background(), &RequestContext{IP: "1.2.3.4"})

	assert.Equal(t, int64(0), resolver.Get("req_per_ip"),
		"an unreadable counter resolves to 0 so the request keeps flowing")

	entries := logs.FilterMessageSnippet("counter read failed").All()
	require.Len(t, entries, 1, "the failure must be logged, not swallowed")
	assert.Equal(t, zap.WarnLevel, entries[0].Level)

	fields := entries[0].ContextMap()
	assert.Equal(t, "req_per_ip", fields["counter"],
		"the log must name which counter failed")
}

// TestCounterResolver_SucceedsQuietly ensures the logging added above does
// not fire on the happy path.
func TestCounterResolver_SucceedsQuietly(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := logging.NewFromZap(zap.New(core))

	store := memory.NewCounterStore()
	defer store.Close()
	// Seed the counter so the read returns a real value rather than a miss.
	_, _, err := store.Incr(context.Background(), "ip_protected_requests_10m", "1.2.3.4", 10*time.Minute)
	require.NoError(t, err)

	reg := NewCounterRegistry(testCounters(), store).WithLogger(logger)
	resolver := reg.LookupResolver(context.Background(), &RequestContext{IP: "1.2.3.4"})
	assert.Equal(t, int64(1), resolver.Get("ip_protected_requests_10m"))

	assert.Zero(t, logs.FilterMessageSnippet("counter read failed").Len(),
		"a successful read must not log a failure")
}
