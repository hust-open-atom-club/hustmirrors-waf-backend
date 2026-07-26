package matcher

import (
	"fmt"
	"regexp"
)

// RegexMatcher reports a path as protected when it matches at least one
// of the configured regular expressions.
//
// patterns is built once by NewRegexMatcher and never mutated, so
// ShouldProtect is safe for concurrent use without locking.
type RegexMatcher struct {
	patterns []*regexp.Regexp
}

func NewRegexMatcher(patterns []string) (*RegexMatcher, error) {
	m := &RegexMatcher{}
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
	for _, re := range m.patterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
