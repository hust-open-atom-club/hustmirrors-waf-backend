package pow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Changing this invalidates all existing sign usage records.
const SignIDVersion = "mirrors-pow-sign-id-v2"

// ComputeSignID returns a stable 64-char hex identifier for a verified
// proof of work.
//
// The id is derived from the token's CANONICAL form - the same string that
// is hashed to produce the sign - and never from the raw token bytes.
//
// This distinction is load-bearing. A payload has many valid encodings:
// trailing whitespace after the JSON object, padded vs unpadded base64url,
// reordered object keys, and so on. All of them decode to the same struct
// and therefore carry the same sign and satisfy the same difficulty, so
// they all represent ONE unit of proof of work. Keying usage records on
// the raw bytes gave each encoding its own record, which reset the
// max_uses counter and let a single PoW solution be redeemed without
// limit.
//
// Anything added here must be a function of the decoded payload, not of
// how it happened to be transmitted.
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

// HashToken hashes the raw token for diagnostic storage only.
//
// It must not be used to derive identity: see ComputeSignID for why the
// raw encoding is not a stable key.
func HashToken(tokenRaw string) string {
	if tokenRaw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tokenRaw))
	return hex.EncodeToString(sum[:])
}
