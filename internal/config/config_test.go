package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyDefaults_FillsRequired(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	assert.Equal(t, "127.0.0.1:8080", c.Server.Listen)
	assert.Equal(t, "token", c.Pow.TokenParam)
	assert.Equal(t, "sign", c.Pow.SignParam)
	assert.Equal(t, 4096, c.Pow.MaxTokenLength)
	assert.Equal(t, 128, c.Pow.MaxSignLength)
	assert.Equal(t, "sha256", c.Pow.Algorithm)
	assert.Equal(t, "memory", c.Storage.Driver)
	assert.Equal(t, "memory", c.Storage.CounterDriver)
	assert.Equal(t, 22, c.Pow.Modes.IPBound.MinDifficulty)
	assert.Equal(t, 28, c.Pow.Modes.IPBound.MaxDifficulty)
	assert.Equal(t, 86400, c.Pow.Modes.IPBound.MaxTTLSeconds)
	assert.Equal(t, 5, c.Pow.Modes.Generic.MaxUses)
	assert.Equal(t, "info", c.Logging.Level)
	assert.Equal(t, "127.0.0.1:8081", c.Admin.Listen)
	assert.Equal(t, 10*time.Minute, c.Cleanup.Interval)
}

func TestValidate_NoModesEnabled(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = false
	c.Pow.Modes.Generic.Enabled = false
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one mode must be enabled")
}

func TestValidate_MinGtMax(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.Pow.Modes.IPBound.MinDifficulty = 30
	c.Pow.Modes.IPBound.MaxDifficulty = 10
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min_difficulty (30) > max_difficulty (10)")
}

func TestValidate_GenericRequiresMaxUses(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = false
	c.Pow.Modes.Generic.Enabled = true
	c.Pow.Modes.Generic.MaxUses = 0
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_uses must be > 0")
}

func TestValidate_BadProtectedRegex(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.Protection.ProtectedPaths = []string{"["}
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not compile")
}

func TestValidate_BadStorageDriver(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.Storage.Driver = "mysql"
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `storage.driver must be one of`)
}

func TestValidate_PostgresRequiresDSN(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.Storage.Driver = "postgres"
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage.postgres.dsn is required")
}

func TestValidate_AdminTokenRequired(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.Admin.Enabled = true
	c.Admin.Auth.Type = "token"
	c.Admin.Auth.TokenFile = ""
	c.Admin.Auth.Token = ""
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin.auth.token_file or admin.auth.token is required")
}

func TestValidate_AdminBadCIDR(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.Admin.Enabled = true
	c.Admin.Auth.Type = "none"
	c.Admin.AllowCIDRs = []string{"not-a-cidr"}
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid CIDR")
}

func TestValidate_RiskControlUnknownJumpChain(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.RiskControl.Enabled = true
	c.RiskControl.Chains = map[string]ChainConfig{
		"INPUT": {
			Policy: PolicyConfig{Target: "ACCEPT", Reason: "ok"},
			Rules: []RuleConfig{
				{Name: "bad jump", Match: MatchConfig{IsProtected: ptrBool(true)}, Target: "JUMP", Chain: "NOPE"},
			},
		},
	}
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `JUMP chain "NOPE" does not exist`)
}

func TestValidate_RiskControlBadLimitRate(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.RiskControl.Enabled = true
	c.RiskControl.Chains = map[string]ChainConfig{
		"INPUT": {
			Policy: PolicyConfig{Target: "ACCEPT", Reason: "ok", LimitRate: "512KB/s"},
		},
	}
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit_rate")
}

func TestValidate_RiskControlCycle(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.RiskControl.Enabled = true
	c.RiskControl.Chains = map[string]ChainConfig{
		"INPUT": {
			Policy: PolicyConfig{Target: "ACCEPT", Reason: "ok"},
			Rules: []RuleConfig{
				{Name: "loop", Match: MatchConfig{}, Target: "JUMP", Chain: "RISK"},
			},
		},
		"RISK": {
			Policy: PolicyConfig{Target: "ACCEPT", Reason: "ok"},
			Rules: []RuleConfig{
				{Name: "back", Match: MatchConfig{}, Target: "JUMP", Chain: "INPUT"},
			},
		},
	}
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
}

func TestValidate_RiskControlCounterMissing(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.RiskControl.Enabled = true
	c.RiskControl.Chains = map[string]ChainConfig{
		"INPUT": {
			Policy: PolicyConfig{Target: "ACCEPT", Reason: "ok"},
			Rules: []RuleConfig{
				{
					Name:   "check missing counter",
					Match:  MatchConfig{Counter: &CounterMatch{Name: "nope", Op: ">=", Value: 1}},
					Target: "REJECT", Reason: "x",
				},
			},
		},
	}
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `counter "nope" is not defined`)
}

func TestValidate_RiskScoreGteIsRejected(t *testing.T) {
	// Nothing in the request pipeline populates a risk score, so a rule
	// using risk_score_gte would compile fine and then silently never
	// match. Validation must surface that instead of failing open.
	threshold := 50
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.RiskControl.Enabled = true
	c.RiskControl.Chains = map[string]ChainConfig{
		"INPUT": {
			Policy: PolicyConfig{Target: "ACCEPT", Reason: "ok"},
			Rules: []RuleConfig{
				{
					Name:   "block high risk",
					Match:  MatchConfig{RiskScoreGte: &threshold},
					Target: "REJECT", Reason: "x",
				},
			},
		},
	}
	err := Validate(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "risk_score_gte is not supported")
}

func TestValidate_GoodConfig_NoError(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	c.Pow.Modes.IPBound.Enabled = true
	c.Pow.Modes.Generic.Enabled = true
	c.Protection.ProtectedPaths = []string{"^/ubuntu/.+\\.iso$"}
	c.Protection.ExcludedPaths = []string{"^/static/"}
	c.RiskControl.Enabled = false
	c.Admin.Enabled = false
	err := Validate(c)
	assert.NoError(t, err)
}

func TestValidationError_Error(t *testing.T) {
	e := &ValidationError{Problems: []string{"a", "b"}}
	s := e.Error()
	assert.True(t, strings.Contains(s, "a"))
	assert.True(t, strings.Contains(s, "b"))
}

func ptrBool(b bool) *bool { return &b }
