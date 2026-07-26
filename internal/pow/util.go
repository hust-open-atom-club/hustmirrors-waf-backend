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

// isCanonicalSafe rejects values that could forge structure inside the
// canonical string.
//
// BuildCanonicalInput joins fields as "key=value" separated by newlines,
// so a value containing a newline can inject additional key=value lines.
// It is applied to path and salt, which unlike cnt have no restricted
// character set of their own.
//
// This is defence in depth rather than a live exploit: path must equal the
// URI Nginx reports, and Go's HTTP parser rejects bare newlines in header
// values, so a crafted path cannot currently reach here. That is a
// property of the components in front of us, not of this package, and it
// should not be what stands between a token and a forged signing input.
func isCanonicalSafe(s string) bool {
	if strings.ContainsAny(s, "\n\r") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
