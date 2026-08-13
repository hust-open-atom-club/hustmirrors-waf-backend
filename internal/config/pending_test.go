package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPendingDefaultsCanBeDisabledExplicitly(t *testing.T) {
	off := false
	c := &Config{}
	c.RiskControl.Pending.Enabled = &off
	applyDefaults(c)

	require.NotNil(t, c.RiskControl.Pending.Enabled)
	assert.False(t, *c.RiskControl.Pending.Enabled)
	assert.Equal(t, 128, c.RiskControl.Pending.MaxPerIP)
	assert.Equal(t, time.Hour, c.RiskControl.Pending.BlockTTL)
}

func TestValidatePendingRejectsInvalidValues(t *testing.T) {
	base := func() *Config {
		c := &Config{}
		applyDefaults(c)
		c.Pow.Modes.IPBound.Enabled = true
		return c
	}

	c := base()
	c.RiskControl.Pending.MaxPerIP = 0
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "risk_control.pending.max_per_ip must be > 0")

	c = base()
	c.RiskControl.Pending.BlockTTL = 0
	err = Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "risk_control.pending.block_ttl must be > 0")

	c = base()
	c.RiskControl.Pending.MaxPerIP = 1_000_001
	err = Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "risk_control.pending.max_per_ip must be <= 1000000")
}
