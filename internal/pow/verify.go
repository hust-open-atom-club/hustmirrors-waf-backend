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

// CompareSign does a case-insensitive comparison rather than constant-time
// compare: the sign value is sha256(canonical), not a MAC key, and the
// canonical input is reconstructible from the token payload which is
// public. Timing side-channels reveal nothing the attacker doesn't
// already know.
//
// If you reuse this function for something else, re-evaluate.
func CompareSign(computedSign, clientSign string) bool {
	if computedSign == "" || clientSign == "" {
		return false
	}
	return strings.EqualFold(computedSign, clientSign)
}
