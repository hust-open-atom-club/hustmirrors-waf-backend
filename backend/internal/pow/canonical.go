package pow

import (
	"fmt"
)

const CanonicalPrefix = "mirrors-pow-v1"

// BuildCanonicalInput constructs the string that is SHA-256'd to produce
// the sign value.
//
// Field order, separators, and the trailing newline are part of the
// canonical format. Changing any of them invalidates every existing token.
func BuildCanonicalInput(p *TokenPayload) string {
	if p == nil {
		return ""
	}
	ip := ""
	if p.Mode == "ip_bound" {
		ip = p.IP
	}
	return fmt.Sprintf(
		CanonicalPrefix+"\n"+
			"mode=%s\n"+
			"ip=%s\n"+
			"path=%s\n"+
			"ts=%d\n"+
			"exp=%d\n"+
			"difficulty=%d\n"+
			"cnt=%s\n"+
			"salt=%s\n",
		p.Mode,
		ip,
		p.Path,
		p.Timestamp,
		p.ExpiresAt,
		p.Difficulty,
		p.Counter,
		p.Salt,
	)
}
