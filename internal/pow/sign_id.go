package pow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Changing this invalidates all existing sign usage records.
const SignIDVersion = "mirrors-pow-sign-id-v1"

// ComputeSignID returns a stable 64-char hex identifier for a
// (tokenRaw, sign, path, mode) tuple.
//
// We hash token+sign rather than using the raw sign as id: different tokens
// could produce the same sign, and a derived id lets us rotate the scheme
// by bumping SignIDVersion without touching the wire protocol.
func ComputeSignID(tokenRaw, sign, path, mode string) string {
	tokenHash := sha256.Sum256([]byte(tokenRaw))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	canonical := fmt.Sprintf(
		SignIDVersion+"\n"+
			"mode=%s\n"+
			"path=%s\n"+
			"token_hash=%s\n"+
			"sign=%s\n",
		mode, path, tokenHashHex, sign,
	)
	id := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(id[:])
}

func HashToken(tokenRaw string) string {
	if tokenRaw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tokenRaw))
	return hex.EncodeToString(sum[:])
}
