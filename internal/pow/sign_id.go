package pow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Changing this invalidates all existing sign usage records.
const SignIDVersion = "mirrors-pow-sign-id-v2"

// ComputeSignID returns a stable 64-char hex id for a verified proof of
// work, derived from the canonical form — never the raw token bytes.
//
// That distinction is load-bearing. One payload has many encodings
// (trailing whitespace, base64 padding), all decoding to the same struct
// with the same sign and difficulty, i.e. one unit of work. Keying on raw
// bytes gave each encoding its own usage record, so max_uses counted
// encodings instead of work and could be bypassed without limit.
//
// Anything added here must be a function of the decoded payload.
func ComputeSignID(p *TokenPayload, sign, mode string) string {
	canonical := fmt.Sprintf(
		SignIDVersion+"\n"+
			"mode=%s\n"+
			"canonical=%s\n"+
			"sign=%s\n",
		mode, BuildCanonicalInput(p), sign,
	)
	id := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(id[:])
}

// HashToken hashes the raw token for diagnostics only. Not an identity —
// see ComputeSignID for why raw bytes aren't a stable key.
func HashToken(tokenRaw string) string {
	if tokenRaw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tokenRaw))
	return hex.EncodeToString(sum[:])
}
