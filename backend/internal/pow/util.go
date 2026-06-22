package pow

import (
	"net/netip"
	"strings"
	"unicode"
)

// isValidIPString uses netip rather than net.ParseIP to reject leading
// zeros in IPv4 octets (which net.ParseIP tolerates).
func isValidIPString(s string) bool {
	if s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err != nil {
		return false
	}
	return true
}

// isCounterSafe rejects characters that could interfere with the canonical
// string (newlines, NUL, etc.). cnt is an opaque nonce — we never
// interpret it as a number.
func isCounterSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'Z':
		case r == '-' || r == '_' || r == '=':
		default:
			return false
		}
		if unicode.IsControl(r) {
			return false
		}
	}
	return !strings.ContainsAny(s, "\n\r\t ")
}
