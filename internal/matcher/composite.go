package matcher

// Composite combines a protected matcher with an optional exclusion
// matcher. A path is protected iff the protected matcher matches AND the
// exclusion matcher does NOT.
//
// Composite is the single entry point the auth service uses, so path
// normalisation happens here: doing it once at the boundary keeps the
// individual matchers simple and makes it impossible for one of them to
// be consulted with a raw path by mistake.
type Composite struct {
	protected Matcher
	excluded  Matcher
}

func NewComposite(protected, excluded Matcher) *Composite {
	return &Composite{protected: protected, excluded: excluded}
}

func (c *Composite) ShouldProtect(path string) bool {
	if c == nil || c.protected == nil {
		return false
	}
	path = NormalizePath(path)
	if !c.protected.ShouldProtect(path) {
		return false
	}
	if c.excluded == nil {
		return true
	}
	return !c.excluded.ShouldProtect(path)
}

func (c *Composite) Protected() Matcher { return c.protected }

func (c *Composite) Excluded() Matcher { return c.excluded }

type NoopMatcher struct{}

func (NoopMatcher) ShouldProtect(_ string) bool { return false }

type AlwaysMatcher struct{}

func (AlwaysMatcher) ShouldProtect(_ string) bool { return true }

var (
	_ Matcher = (*Composite)(nil)
	_ Matcher = NoopMatcher{}
	_ Matcher = AlwaysMatcher{}
	_ Matcher = (*ExtensionMatcher)(nil)
	_ Matcher = (*RegexMatcher)(nil)
)
