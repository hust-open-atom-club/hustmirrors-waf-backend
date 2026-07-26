package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNormalizePath_ClosesSuffixBypasses is the regression guard for a
// protection bypass. Protection is decided by suffix and regex, so any
// transformation that alters the tail while still naming the same file
// reads as "not protected". All of these were observed reaching
// reason=not_protected against a .iso.
func TestNormalizePath_ClosesSuffixBypasses(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"percent-encoded dot", "/ubuntu%2Eiso", "/ubuntu.iso"},
		{"percent-encoded uppercase", "/ubuntu%2eiso", "/ubuntu.iso"},
		{"trailing slash", "/ubuntu.iso/", "/ubuntu.iso"},
		{"trailing dot", "/ubuntu.iso.", "/ubuntu.iso"},
		{"trailing space", "/ubuntu.iso ", "/ubuntu.iso"},
		{"trailing tab", "/ubuntu.iso\t", "/ubuntu.iso"},
		{"repeated trailing junk", "/ubuntu.iso/.. ", "/ubuntu.iso"},
		{"path parameter", "/ubuntu.iso;x=1", "/ubuntu.iso"},
		{"NUL truncation", "/ubuntu.iso\x00.txt", "/ubuntu.iso"},
		{"encoded NUL", "/ubuntu.iso%00.txt", "/ubuntu.iso"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NormalizePath(tc.in))
		})
	}
}

// TestNormalizePath_LeavesLegitimatePathsAlone ensures normalisation does
// not silently change which file a request names. Over-normalising would
// be its own bug: it could mark an unrelated path as protected, or worse,
// disagree with what the proxy actually serves.
func TestNormalizePath_LeavesLegitimatePathsAlone(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"plain", "/ubuntu.iso", "/ubuntu.iso"},
		{"nested", "/releases/24.04/ubuntu.iso", "/releases/24.04/ubuntu.iso"},
		{"dot in directory", "/v1.0/file.iso", "/v1.0/file.iso"},
		{"semicolon in earlier segment", "/a;b/ubuntu.iso", "/a;b/ubuntu.iso"},
		{"encoded space in name", "/my%20file.iso", "/my file.iso"},
		{"empty", "", ""},
		// ".." resolution belongs to the proxy; guessing here could
		// disagree with what is actually served.
		{"traversal is left intact", "/a/../ubuntu.iso", "/a/../ubuntu.iso"},
		{"double slash is left intact", "//ubuntu.iso", "//ubuntu.iso"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NormalizePath(tc.in))
		})
	}
}

// TestNormalizePath_MalformedEscapeFailsClosed pins that an undecodable
// percent sequence is left alone rather than dropped. Returning "" or a
// truncated value would make a malformed path unprotected.
func TestNormalizePath_MalformedEscapeFailsClosed(t *testing.T) {
	assert.Equal(t, "/ubuntu%zz.iso", NormalizePath("/ubuntu%zz.iso"))
	assert.Equal(t, "/ubuntu%2.iso", NormalizePath("/ubuntu%2.iso"))
}

// TestComposite_NormalizesBeforeMatching wires the above through the type
// the auth service actually calls, so the normalisation cannot be lost by
// a future refactor that bypasses Composite.
func TestComposite_NormalizesBeforeMatching(t *testing.T) {
	ext := NewExtensionMatcher([]string{".iso"})
	c := NewComposite(ext, nil)

	for _, uri := range []string{
		"/ubuntu.iso",
		"/ubuntu%2Eiso",
		"/ubuntu.iso/",
		"/ubuntu.iso.",
		"/ubuntu.iso ",
		"/ubuntu.iso;x=1",
		"/ubuntu.iso\x00.txt",
	} {
		assert.True(t, c.ShouldProtect(uri),
			"%q names a .iso and must be protected", uri)
	}

	assert.False(t, c.ShouldProtect("/index.html"))
	assert.False(t, c.ShouldProtect(""))
}

// TestComposite_NormalizationAppliesToExclusions guards the opposite
// direction: an exclusion must not be evadable either, or a path the
// operator meant to exempt could be forced back under protection.
func TestComposite_NormalizationAppliesToExclusions(t *testing.T) {
	ext := NewExtensionMatcher([]string{".iso"})
	excl, err := NewRegexMatcher([]string{`^/public/`})
	if err != nil {
		t.Fatal(err)
	}
	c := NewComposite(ext, excl)

	assert.False(t, c.ShouldProtect("/public/ubuntu.iso"))
	assert.False(t, c.ShouldProtect("/public/ubuntu%2Eiso"),
		"an excluded path stays excluded after normalisation")
	assert.True(t, c.ShouldProtect("/private/ubuntu.iso"))
}
