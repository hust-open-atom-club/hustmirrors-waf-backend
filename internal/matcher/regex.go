package matcher

import (
	"fmt"
	"regexp"
	"sync"
)

// RegexMatcher reports a path as protected when it matches at least one
// of the configured regular expressions.
type RegexMatcher struct {
	patterns []*regexp.Regexp
	raw      []string
	mu       sync.RWMutex
}

func NewRegexMatcher(patterns []string) (*RegexMatcher, error) {
	m := &RegexMatcher{raw: append([]string(nil), patterns...)}
	var errs []string
	for _, p := range patterns {
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			errs = append(errs, fmt.Sprintf("pattern %q: %v", p, err))
			continue
		}
		m.patterns = append(m.patterns, re)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("matcher: invalid regex patterns: %v", errs)
	}
	return m, nil
}

func (m *RegexMatcher) ShouldProtect(path string) bool {
	if path == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, re := range m.patterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (m *RegexMatcher) Patterns() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.raw))
	copy(out, m.raw)
	return out
}
