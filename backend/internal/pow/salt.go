package pow

import "strings"

// SaltAllowed reports whether the given token salt is acceptable given the
// runtime configuration.
//
// Empty salt is allowed only when allowEmpty is true; otherwise the salt
// must match one of allowedSalts (case-insensitive).
func SaltAllowed(salt string, allowedSalts []string, allowEmpty bool) bool {
	if salt == "" {
		return allowEmpty
	}
	for _, s := range allowedSalts {
		if strings.EqualFold(s, salt) {
			return true
		}
	}
	return false
}
