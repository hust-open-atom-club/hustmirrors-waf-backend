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

// CompareSign compares a computed sign against a client-supplied one.
//
// This deliberately uses a plain case-insensitive comparison rather than
// crypto/subtle.ConstantTimeCompare, because there is no secret to leak:
//
//   - sign is sha256(canonical), not a MAC — no key is involved.
//   - The canonical input (mode, ip, path, ts, exp, difficulty, cnt, salt)
//     is built entirely from fields the client already sent in its own
//     token, so the attacker knows every byte of it.
//   - public_salt is served to the browser in the frontend config.json.
//     It exists to stop precomputed dictionaries, not to stay secret.
//
// A timing side-channel here would reveal only how many leading hex digits
// of a value the attacker can already compute themselves match. The real
// cost of forging a token is the difficulty check in HasLeadingZeroBits32,
// which no timing observation helps with.
//
// If a secret is ever introduced into the canonical input, or this
// function is reused to compare a MAC or session token, switch to
// subtle.ConstantTimeCompare.
func CompareSign(computedSign, clientSign string) bool {
	if computedSign == "" || clientSign == "" {
		return false
	}
	return strings.EqualFold(computedSign, clientSign)
}
