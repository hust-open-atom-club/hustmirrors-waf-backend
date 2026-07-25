package matcher

// Matcher is the path-protection predicate used by the auth service.
type Matcher interface {
	ShouldProtect(path string) bool
}
