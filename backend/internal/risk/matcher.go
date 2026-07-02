package risk

import (
	"net"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"sync"
)

// Matcher is a compiled MatchConfig. Implementations must be safe for
// concurrent use.
type Matcher interface {
	Match(ctx *RequestContext) bool
}

// MatchConfig is the YAML representation of a rule's match condition.
// Re-declared here (rather than importing internal/config) to keep the
// risk package free of the config package.
type MatchConfig struct {
	PathRegex      string
	PathPrefix     string
	ExtensionIn    []string
	MethodIn       []string
	IPCIDRIn       []string
	UserAgentRegex string
	PowStatus      string
	PowStatusIn    []string
	PowMode        string
	IsProtected    *bool
	IsRangeRequest *bool
	Counter        *CounterMatch
	RiskScoreGte   *int
}

type CounterMatch struct {
	Name  string
	Op    string
	Value int64
}

func CompileMatcher(m MatchConfig) (Matcher, error) {
	var parts []Matcher
	if m.PathRegex != "" {
		re, err := regexp.Compile(m.PathRegex)
		if err != nil {
			return nil, err
		}
		parts = append(parts, pathRegexMatcher{re: re})
	}
	if m.PathPrefix != "" {
		parts = append(parts, pathPrefixMatcher{p: m.PathPrefix})
	}
	if len(m.ExtensionIn) > 0 {
		exts := make([]string, 0, len(m.ExtensionIn))
		for _, e := range m.ExtensionIn {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" {
				continue
			}
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			exts = append(exts, e)
		}
		parts = append(parts, extensionMatcher{exts: exts})
	}
	if len(m.MethodIn) > 0 {
		methods := make(map[string]struct{}, len(m.MethodIn))
		for _, mm := range m.MethodIn {
			methods[strings.ToUpper(strings.TrimSpace(mm))] = struct{}{}
		}
		parts = append(parts, methodMatcher{methods: methods})
	}
	if len(m.IPCIDRIn) > 0 {
		nets := make([]*net.IPNet, 0, len(m.IPCIDRIn))
		for _, c := range m.IPCIDRIn {
			_, ipnet, err := net.ParseCIDR(c)
			if err != nil {
				return nil, err
			}
			nets = append(nets, ipnet)
		}
		parts = append(parts, &ipCIDRMatcher{nets: nets})
	}
	if m.UserAgentRegex != "" {
		re, err := regexp.Compile(m.UserAgentRegex)
		if err != nil {
			return nil, err
		}
		parts = append(parts, uaRegexMatcher{re: re})
	}
	if m.PowStatus != "" {
		parts = append(parts, powStatusMatcher{s: m.PowStatus})
	}
	if len(m.PowStatusIn) > 0 {
		statuses := make(map[string]struct{}, len(m.PowStatusIn))
		for _, s := range m.PowStatusIn {
			statuses[s] = struct{}{}
		}
		parts = append(parts, powStatusInMatcher{s: statuses})
	}
	if m.PowMode != "" {
		parts = append(parts, powModeMatcher{m: m.PowMode})
	}
	if m.IsProtected != nil {
		parts = append(parts, boolMatcher{field: "is_protected", want: *m.IsProtected})
	}
	if m.IsRangeRequest != nil {
		parts = append(parts, boolMatcher{field: "is_range_request", want: *m.IsRangeRequest})
	}
	if m.Counter != nil {
		parts = append(parts, counterMatcher{c: *m.Counter})
	}
	if m.RiskScoreGte != nil {
		parts = append(parts, riskScoreMatcher{threshold: *m.RiskScoreGte})
	}
	if len(parts) == 0 {
		return matchAll{}, nil
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return andMatcher{parts: parts}, nil
}

type matchAll struct{}

func (matchAll) Match(_ *RequestContext) bool { return true }

type pathRegexMatcher struct{ re *regexp.Regexp }

func (m pathRegexMatcher) Match(ctx *RequestContext) bool {
	return m.re.MatchString(ctx.Path)
}

type pathPrefixMatcher struct{ p string }

func (m pathPrefixMatcher) Match(ctx *RequestContext) bool {
	return strings.HasPrefix(ctx.Path, m.p)
}

type extensionMatcher struct{ exts []string }

func (m extensionMatcher) Match(ctx *RequestContext) bool {
	ext := strings.ToLower(path.Ext(ctx.Path))
	if ext == "" {
		return false
	}
	for _, e := range m.exts {
		if e == ext {
			return true
		}
	}
	return false
}

type methodMatcher struct{ methods map[string]struct{} }

func (m methodMatcher) Match(ctx *RequestContext) bool {
	_, ok := m.methods[strings.ToUpper(ctx.Method)]
	return ok
}

type ipCIDRMatcher struct {
	nets []*net.IPNet
	mu   sync.Mutex // net.IPNet.Contains is not documented as thread-safe
}

func (m *ipCIDRMatcher) Match(ctx *RequestContext) bool {
	addr, err := netip.ParseAddr(ctx.IP)
	if err != nil {
		return false
	}
	ip := net.IP(addr.AsSlice())
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type uaRegexMatcher struct{ re *regexp.Regexp }

func (m uaRegexMatcher) Match(ctx *RequestContext) bool {
	return m.re.MatchString(ctx.UserAgent)
}

type powStatusMatcher struct{ s string }

func (m powStatusMatcher) Match(ctx *RequestContext) bool { return ctx.PowStatus == m.s }

type powStatusInMatcher struct{ s map[string]struct{} }

func (m powStatusInMatcher) Match(ctx *RequestContext) bool {
	_, ok := m.s[ctx.PowStatus]
	return ok
}

type powModeMatcher struct{ m string }

func (m powModeMatcher) Match(ctx *RequestContext) bool { return ctx.PowMode == m.m }

type boolMatcher struct {
	field string
	want  bool
}

func (m boolMatcher) Match(ctx *RequestContext) bool {
	switch m.field {
	case "is_protected":
		return ctx.IsProtected == m.want
	case "is_range_request":
		return ctx.IsRangeRequest == m.want
	}
	return false
}

type counterMatcher struct{ c CounterMatch }

func (m counterMatcher) Match(ctx *RequestContext) bool {
	if ctx.Counters == nil {
		return false
	}
	v := ctx.Counters.Get(m.c.Name)
	return compareCounter(v, m.c.Op, m.c.Value)
}

type riskScoreMatcher struct{ threshold int }

func (m riskScoreMatcher) Match(ctx *RequestContext) bool { return ctx.RiskScore >= m.threshold }

type andMatcher struct{ parts []Matcher }

func (m andMatcher) Match(ctx *RequestContext) bool {
	for _, p := range m.parts {
		if !p.Match(ctx) {
			return false
		}
	}
	return true
}

func compareCounter(v int64, op string, target int64) bool {
	switch op {
	case ">=":
		return v >= target
	case ">":
		return v > target
	case "==":
		return v == target
	case "!=":
		return v != target
	case "<=":
		return v <= target
	case "<":
		return v < target
	}
	return false
}

var (
	_ Matcher = matchAll{}
	_ Matcher = pathRegexMatcher{}
	_ Matcher = pathPrefixMatcher{}
	_ Matcher = extensionMatcher{}
	_ Matcher = methodMatcher{}
	_ Matcher = (*ipCIDRMatcher)(nil)
	_ Matcher = uaRegexMatcher{}
	_ Matcher = powStatusMatcher{}
	_ Matcher = powStatusInMatcher{}
	_ Matcher = powModeMatcher{}
	_ Matcher = boolMatcher{}
	_ Matcher = counterMatcher{}
	_ Matcher = riskScoreMatcher{}
	_ Matcher = andMatcher{}
)
