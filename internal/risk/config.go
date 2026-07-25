package risk

import (
	"fmt"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
)

func FromConfig(rc config.RiskControlConfig) (*Engine, error) {
	if !rc.Enabled {
		return nil, fmt.Errorf("risk: risk_control is disabled")
	}
	chains := make(ChainMap, len(rc.Chains))
	for name, cc := range rc.Chains {
		chain, err := compileChain(name, cc)
		if err != nil {
			return nil, fmt.Errorf("risk: chain %q: %w", name, err)
		}
		chains[name] = chain
	}
	return NewEngine(chains)
}

func compileChain(name string, cc config.ChainConfig) (*Chain, error) {
	if !isValidPolicyTarget(cc.Policy.Target) {
		return nil, fmt.Errorf("policy target %q is not a valid policy target", cc.Policy.Target)
	}
	chain := &Chain{
		Name: name,
		Policy: Policy{
			Target:    cc.Policy.Target,
			Status:    cc.Policy.Status,
			LimitRate: cc.Policy.LimitRate,
			Reason:    cc.Policy.Reason,
		},
	}
	for i, rc := range cc.Rules {
		rule, err := compileRule(rc)
		if err != nil {
			return nil, fmt.Errorf("rule[%d] %q: %w", i, rc.Name, err)
		}
		chain.Rules = append(chain.Rules, rule)
	}
	return chain, nil
}

func compileRule(rc config.RuleConfig) (Rule, error) {
	if !isValidRuleTarget(rc.Target) {
		return Rule{}, fmt.Errorf("target %q is not supported", rc.Target)
	}
	m, err := CompileMatcher(MatchConfig{
		PathRegex:      rc.Match.PathRegex,
		PathPrefix:     rc.Match.PathPrefix,
		ExtensionIn:    rc.Match.ExtensionIn,
		MethodIn:       rc.Match.MethodIn,
		IPCIDRIn:       rc.Match.IPCIDRIn,
		UserAgentRegex: rc.Match.UserAgentRegex,
		PowStatus:      rc.Match.PowStatus,
		PowStatusIn:    rc.Match.PowStatusIn,
		PowMode:        rc.Match.PowMode,
		IsProtected:    rc.Match.IsProtected,
		IsRangeRequest: rc.Match.IsRangeRequest,
		Counter:        convertCounter(rc.Match.Counter),
		RiskScoreGte:   rc.Match.RiskScoreGte,
	})
	if err != nil {
		return Rule{}, err
	}
	return Rule{
		Name:      rc.Name,
		Match:     m,
		Target:    rc.Target,
		Chain:     rc.Chain,
		Status:    rc.Status,
		LimitRate: rc.LimitRate,
		Reason:    rc.Reason,
		Mark:      rc.Mark,
	}, nil
}

func convertCounter(c *config.CounterMatch) *CounterMatch {
	if c == nil {
		return nil
	}
	return &CounterMatch{Name: c.Name, Op: c.Op, Value: c.Value}
}
