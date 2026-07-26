package pow

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func ComputeSign(p *TokenPayload) string {
	canonical := BuildCanonicalInput(p)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func HashCanonical(canonical string) [32]byte {
	return sha256.Sum256([]byte(canonical))
}

// CompareSign is intentionally not constant-time. sign is sha256(canonical),
// not a MAC, and the canonical input is built entirely from fields the
// client sent in its own token — public_salt included, which ships to the
// browser in config.json. There is no secret whose byte positions a timing
// channel could reveal. Forging a token is gated by the difficulty check,
// which timing doesn't help with.
//
// Revisit if a secret ever enters the canonical input, or if this is reused
// for a MAC or session token.
func CompareSign(computedSign, clientSign string) bool {
	if computedSign == "" || clientSign == "" {
		return false
	}
	return strings.EqualFold(computedSign, clientSign)
}
