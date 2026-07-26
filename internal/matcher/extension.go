package matcher

import (
	"strings"
)

// ExtensionMatcher reports a path as protected when its suffix matches one
// of the configured extensions. Matching is case-insensitive and treats
// compound suffixes like ".tar.gz" by literal string suffix comparison.
//
// exts is built once by NewExtensionMatcher and never mutated, so
// ShouldProtect is safe for concurrent use without locking.
type ExtensionMatcher struct {
	exts   []string
	extSet map[string]struct{}
}

func NewExtensionMatcher(extensions []string) *ExtensionMatcher {
	m := &ExtensionMatcher{extSet: make(map[string]struct{}, len(extensions))}
	for _, e := range extensions {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if _, ok := m.extSet[e]; ok {
			continue
		}
		m.extSet[e] = struct{}{}
		m.exts = append(m.exts, e)
	}
	return m
}

func (m *ExtensionMatcher) ShouldProtect(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(path)
	for _, e := range m.exts {
		if strings.HasSuffix(lower, e) {
			return true
		}
	}
	return false
}

// Extensions returns the normalised extension list. Used by tests and by
// the admin API's config introspection.
func (m *ExtensionMatcher) Extensions() []string {
	out := make([]string, len(m.exts))
	copy(out, m.exts)
	return out
}
