package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ValidationError carries one or more configuration problems.
type ValidationError struct {
	Problems []string
}

func (e ValidationError) Error() string {
	if len(e.Problems) == 0 {
		return "config validation failed"
	}
	return "config validation failed:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// add records a problem.
func (e *ValidationError) add(format string, args ...any) {
	e.Problems = append(e.Problems, fmt.Sprintf(format, args...))
}

func (e *ValidationError) has() bool { return len(e.Problems) > 0 }

func Validate(c *Config) error {
	var e ValidationError

	if !c.Pow.Modes.IPBound.Enabled && !c.Pow.Modes.Generic.Enabled {
		e.add("pow.modes: at least one mode must be enabled")
	}

	e.checkModeDifficulty("ip_bound", c.Pow.Modes.IPBound)
	e.checkModeDifficulty("generic", c.Pow.Modes.Generic)

	if c.Pow.Modes.IPBound.Enabled && c.Pow.Modes.IPBound.MaxTTLSeconds <= 0 {
		e.add("pow.modes.ip_bound.max_ttl_seconds must be > 0")
	}
	if c.Pow.Modes.Generic.Enabled && c.Pow.Modes.Generic.MaxTTLSeconds <= 0 {
		e.add("pow.modes.generic.max_ttl_seconds must be > 0")
	}

	if c.Pow.Modes.Generic.Enabled && c.Pow.Modes.Generic.MaxUses <= 0 {
		e.add("pow.modes.generic.max_uses must be > 0 when generic mode is enabled")
	}

	for _, re := range c.Protection.ProtectedPaths {
		if _, err := regexp.Compile(re); err != nil {
			e.add("protection.protected_paths: %q does not compile: %v", re, err)
		}
	}
	for _, re := range c.Protection.ExcludedPaths {
		if _, err := regexp.Compile(re); err != nil {
			e.add("protection.excluded_paths: %q does not compile: %v", re, err)
		}
	}

	switch c.Storage.Driver {
	case "memory", "postgres":
	default:
		e.add("storage.driver must be one of: memory, postgres (got %q)", c.Storage.Driver)
	}
	switch c.Storage.CounterDriver {
	case "memory", "redis":
	default:
		e.add("storage.counter_driver must be one of: memory, redis (got %q)", c.Storage.CounterDriver)
	}

	if c.Storage.Driver == "postgres" && c.Storage.Postgres.DSN == "" {
		e.add("storage.postgres.dsn is required when storage.driver=postgres")
	}

	if c.Pow.TokenParam == "" {
		e.add("pow.token_param must not be empty")
	}
	if c.Pow.SignParam == "" {
		e.add("pow.sign_param must not be empty")
	}

	if c.RiskControl.Enabled {
		e.checkRiskControl(c.RiskControl)
	}

	if c.Admin.Enabled {
		e.checkAdmin(c.Admin)
	}

	if c.Server.ReadTimeout <= 0 {
		e.add("server.read_timeout must be > 0")
	}
	if c.Server.ShutdownTimeout < 0 {
		e.add("server.shutdown_timeout must be >= 0")
	}

	if e.has() {
		return e
	}
	return nil
}

func (e *ValidationError) checkModeDifficulty(name string, m ModeConfig) {
	if m.MinDifficulty < 0 || m.MaxDifficulty < 0 {
		e.add("pow.modes.%s: difficulties must be non-negative", name)
		return
	}
	if m.MinDifficulty > m.MaxDifficulty {
		e.add("pow.modes.%s: min_difficulty (%d) > max_difficulty (%d)", name, m.MinDifficulty, m.MaxDifficulty)
	}
}

func (e *ValidationError) checkRiskControl(rc RiskControlConfig) {
	if len(rc.Chains) == 0 {
		e.add("risk_control.chains: at least one chain is required")
	}
	for chainName, chain := range rc.Chains {
		if chain.Policy.Target == "" {
			e.add("risk_control.chains.%s: policy.target must be set", chainName)
		}
		if !isValidTarget(chain.Policy.Target, true) {
			e.add("risk_control.chains.%s: policy.target %q is not a valid policy target", chainName, chain.Policy.Target)
		}
		if chain.Policy.LimitRate != "" && !isValidLimitRate(chain.Policy.LimitRate) {
			e.add("risk_control.chains.%s.policy: limit_rate %q is malformed", chainName, chain.Policy.LimitRate)
		}

		for i, rule := range chain.Rules {
			if rule.Name == "" {
				e.add("risk_control.chains.%s.rules[%d]: name is required", chainName, i)
			}
			if !isValidTarget(rule.Target, false) {
				e.add("risk_control.chains.%s.rules[%d]: target %q is not supported", chainName, i, rule.Target)
			}
			if rule.Match.PathRegex != "" {
				if _, err := regexp.Compile(rule.Match.PathRegex); err != nil {
					e.add("risk_control.chains.%s.rules[%d]: path_regex %q does not compile: %v", chainName, i, rule.Match.PathRegex, err)
				}
			}
			if rule.Match.UserAgentRegex != "" {
				if _, err := regexp.Compile(rule.Match.UserAgentRegex); err != nil {
					e.add("risk_control.chains.%s.rules[%d]: user_agent_regex %q does not compile: %v", chainName, i, rule.Match.UserAgentRegex, err)
				}
			}
			if rule.LimitRate != "" && !isValidLimitRate(rule.LimitRate) {
				e.add("risk_control.chains.%s.rules[%d]: limit_rate %q is malformed", chainName, i, rule.LimitRate)
			}
			// viper lowercases map keys during decode, so JUMP chain
			// lookups must be case-insensitive.
			if rule.Target == "JUMP" {
				if rule.Chain == "" {
					e.add("risk_control.chains.%s.rules[%d]: JUMP target requires chain field", chainName, i)
				} else if !chainExistsCaseInsensitive(rc.Chains, rule.Chain) {
					e.add("risk_control.chains.%s.rules[%d]: JUMP chain %q does not exist", chainName, i, rule.Chain)
				}
			}
			if rule.Match.Counter != nil {
				if rule.Match.Counter.Name == "" {
					e.add("risk_control.chains.%s.rules[%d]: counter.name is required", chainName, i)
				} else if _, ok := rc.Counters[rule.Match.Counter.Name]; !ok {
					e.add("risk_control.chains.%s.rules[%d]: counter %q is not defined", chainName, i, rule.Match.Counter.Name)
				}
				if !isValidCounterOp(rule.Match.Counter.Op) {
					e.add("risk_control.chains.%s.rules[%d]: counter.op %q is not supported", chainName, i, rule.Match.Counter.Op)
				}
			}
		}
	}

	e.detectCycles(rc)

	for name, ctr := range rc.Counters {
		if ctr.Window <= 0 {
			e.add("risk_control.counters.%s: window must be > 0", name)
		}
		if ctr.Key == "" {
			e.add("risk_control.counters.%s: key must be set", name)
		}
		switch ctr.Storage {
		case "", "memory", "redis":
		default:
			e.add("risk_control.counters.%s: storage %q is not supported", name, ctr.Storage)
		}
	}
}

func (e *ValidationError) checkAdmin(a AdminConfig) {
	if a.Listen == "" {
		e.add("admin.listen must not be empty")
	}
	switch a.Auth.Type {
	case "token":
		if a.Auth.TokenFile == "" && a.Auth.Token == "" {
			e.add("admin.auth.token_file or admin.auth.token is required when type=token")
		}
	case "basic":
		if a.Auth.Username == "" || a.Auth.Password == "" {
			e.add("admin.auth.username/password required when type=basic")
		}
	case "none", "":
	default:
		e.add("admin.auth.type %q is not supported", a.Auth.Type)
	}
	for i, cidr := range a.AllowCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			e.add("admin.allow_cidrs[%d]: %q is not a valid CIDR", i, cidr)
		}
	}
}

// policy=true means we are validating a chain policy target
// (JUMP/RETURN/LOG/MARK are not valid as a policy).
func isValidTarget(t string, policy bool) bool {
	switch t {
	case "ACCEPT", "REJECT", "RATE_LIMIT", "TOO_MANY", "REQUIRE_POW":
		return true
	case "JUMP", "RETURN", "LOG", "MARK":
		return !policy
	case "":
		return false
	}
	return false
}

var limitRateRe = regexp.MustCompile(`^[0-9]+[kKmMgG]?$`)

// accepts "0" (no limit) or "<n>[kKmMgG]".
func isValidLimitRate(s string) bool {
	if s == "0" {
		return true
	}
	return limitRateRe.MatchString(s)
}

func isValidCounterOp(op string) bool {
	switch op {
	case "==", "!=", ">=", ">", "<=", "<":
		return true
	}
	return false
}

// chainExistsCaseInsensitive does a case-insensitive comparison so YAML keys
// like "input" (lowercased by viper) still match "INPUT".
func chainExistsCaseInsensitive(chains map[string]ChainConfig, name string) bool {
	if _, ok := chains[name]; ok {
		return true
	}
	upper := strings.ToUpper(name)
	for k := range chains {
		if strings.ToUpper(k) == upper {
			return true
		}
	}
	return false
}

func (e *ValidationError) detectCycles(rc RiskControlConfig) {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	normalised := make(map[string]ChainConfig, len(rc.Chains))
	for k, v := range rc.Chains {
		normalised[strings.ToUpper(k)] = v
	}
	color := make(map[string]int, len(normalised))
	var visit func(name string, path []string) bool
	visit = func(name string, path []string) bool {
		upper := strings.ToUpper(name)
		if color[upper] == gray {
			e.add("risk_control.chains: cycle detected: %s -> %s", strings.Join(path, " -> "), name)
			return true
		}
		if color[upper] == black {
			return false
		}
		color[upper] = gray
		chain, ok := normalised[upper]
		if !ok {
			// Unknown JUMP target is reported elsewhere; treat as leaf here.
			color[upper] = black
			return false
		}
		for _, r := range chain.Rules {
			if r.Target == "JUMP" && r.Chain != "" {
				if visit(r.Chain, append(path, name)) {
					return true
				}
			}
		}
		color[upper] = black
		return false
	}
	for n := range normalised {
		visit(n, nil)
	}
}
