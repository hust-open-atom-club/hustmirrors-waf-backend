package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_AllCollectorsPresent(t *testing.T) {
	c := New()
	require.NotNil(t, c.PowVerifyTotal)
	require.NotNil(t, c.PowVerifyLatencySeconds)
	require.NotNil(t, c.RiskDecisionTotal)
	require.NotNil(t, c.StorageOperations)
	require.NotNil(t, c.StorageLatencySeconds)
	require.NotNil(t, c.ActiveSignatures)
	require.NotNil(t, c.PendingAutoBlocks)
	require.NotNil(t, c.PowFlags)
}

func TestContainer_Register_IncrementsSafely(t *testing.T) {
	c := New()
	c.PowVerifyTotal.WithLabelValues("allow", "generic_valid", "generic", "true").Inc()
	c.PowVerifyLatencySeconds.WithLabelValues("generic").Observe(0.001)
	c.RiskDecisionTotal.WithLabelValues("ACCEPT", "valid_pow_full_speed").Inc()
	c.StorageOperations.WithLabelValues("memory", "consume", "ok").Inc()
	c.StorageLatencySeconds.WithLabelValues("memory", "consume").Observe(0.0005)
	c.ActiveSignatures.Set(42)
	c.PendingAutoBlocks.Inc()
	c.PowFlags.WithLabelValues("dry_run").Set(BoolValue(true))

	_ = c.Register()
	assert.NotNil(t, c)
}
