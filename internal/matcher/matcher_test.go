package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtensionMatcher_ShouldProtect(t *testing.T) {
	m := NewExtensionMatcher([]string{".iso", "img", ".TAR.GZ"})
	cases := []struct {
		path string
		want bool
	}{
		{"/ubuntu-22.04.iso", true},
		{"/ubuntu-22.04.ISO", true},
		{"/disk.img", true},
		{"/disk.IMG", true},
		{"/ubuntu.tar.gz", true},
		{"/ubuntu.TAR.GZ", true},
		{"/ubuntu.tar", false},
		{"/index.html", false},
		{"", false},
		{"/Packages.gz", false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			assert.Equal(t, c.want, m.ShouldProtect(c.path))
		})
	}
}

func TestExtensionMatcher_DedupesAndNormalises(t *testing.T) {
	m := NewExtensionMatcher([]string{".iso", "iso", ".ISO"})
	exts := m.Extensions()
	assert.Equal(t, []string{".iso"}, exts)
}

func TestRegexMatcher(t *testing.T) {
	m, err := NewRegexMatcher([]string{
		`^/ubuntu-releases/.+\.iso$`,
		`^/debian-cd/.+\.iso$`,
	})
	require.NoError(t, err)
	assert.True(t, m.ShouldProtect("/ubuntu-releases/22.04/ubuntu-22.04.iso"))
	assert.True(t, m.ShouldProtect("/debian-cd/12/debian-12.iso"))
	assert.False(t, m.ShouldProtect("/ubuntu-releases/22.04/SHA256SUMS"))
}

func TestRegexMatcher_BadPatternReturnsError(t *testing.T) {
	_, err := NewRegexMatcher([]string{"["})
	require.Error(t, err)
}

func TestComposite_ProtectedAndNotExcluded(t *testing.T) {
	ext, err := NewRegexMatcher([]string{`\.(iso|img)$`})
	require.NoError(t, err)
	exc, err := NewRegexMatcher([]string{`^/assets/`, `^/\.well-known/`})
	require.NoError(t, err)
	c := NewComposite(ext, exc)
	assert.True(t, c.ShouldProtect("/x.iso"))
	assert.False(t, c.ShouldProtect("/assets/x.iso"))
	assert.True(t, c.ShouldProtect("/ubuntu/x.img"))
}

func TestComposite_NilProtected(t *testing.T) {
	c := NewComposite(nil, nil)
	assert.False(t, c.ShouldProtect("/x.iso"))
}

func TestComposite_NilExcluded(t *testing.T) {
	ext, err := NewRegexMatcher([]string{`\.iso$`})
	require.NoError(t, err)
	c := NewComposite(ext, nil)
	assert.True(t, c.ShouldProtect("/x.iso"))
}

func TestNoopMatcher(t *testing.T) {
	assert.False(t, NoopMatcher{}.ShouldProtect("/anything"))
}

func TestAlwaysMatcher(t *testing.T) {
	assert.True(t, AlwaysMatcher{}.ShouldProtect("/anything"))
}

// Test the full default protection rules to make sure the matcher behaves
// as the design doc expects.
func TestDefaultRules(t *testing.T) {
	exts := NewExtensionMatcher([]string{
		".iso", ".img", ".qcow2", ".vmdk", ".vdi", ".ova",
		".zip", ".7z", ".tar", ".tar.gz", ".tar.xz",
	})
	protected, err := NewRegexMatcher([]string{
		`^/ubuntu-releases/.+\.iso$`,
		`^/debian-cd/.+\.iso$`,
		`^/archlinux/iso/.+\.iso$`,
	})
	require.NoError(t, err)
	excluded, err := NewRegexMatcher([]string{
		`^/assets/`,
		`^/static/`,
		`^/\.well-known/`,
		`^/.+/Packages(\.gz|\.xz|\.zst)?$`,
		`^/.+/Release$`,
		`^/.+/InRelease$`,
		`^/.+/repomd\.xml$`,
	})
	require.NoError(t, err)
	// protected ∪ regex-protected, then minus excluded.
	// The Composite uses a single "protected" matcher; for the union we
	// use a helper matcher that delegates to both exts and regex-protected.
	combined := unionMatcher{a: exts, b: protected}
	m := NewComposite(combined, excluded)

	cases := []struct {
		path string
		want bool
	}{
		{"/ubuntu-releases/22.04/ubuntu-22.04.iso", true},
		{"/debian-cd/12/debian-12.iso", true},
		{"/archlinux/iso/2024.01.01/archlinux.iso", true},
		{"/random/file.iso", true},
		{"/random/file.7z", true},
		{"/assets/thing.iso", false},
		{"/static/file.tar.gz", false},
		{"/.well-known/file.iso", false},
		{"/ubuntu/Packages", false},
		{"/ubuntu/Packages.gz", false},
		{"/ubuntu/Release", false},
		{"/ubuntu/InRelease", false},
		{"/ubuntu/repomd.xml", false},
		{"/ubuntu/repomd.xml.asc", false}, // .asc not in protected extensions
		{"/index.html", false},
		{"/README", false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			assert.Equal(t, c.want, m.ShouldProtect(c.path))
		})
	}
}

// unionMatcher is a small test helper that ORs two matchers.
type unionMatcher struct{ a, b Matcher }

func (u unionMatcher) ShouldProtect(p string) bool {
	return u.a.ShouldProtect(p) || u.b.ShouldProtect(p)
}
