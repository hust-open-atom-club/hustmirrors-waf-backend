package pow

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFrontendCanonicalCompatibility verifies that the canonical string
// format produced by deploy/frontend/pow.js matches what the backend's
// BuildCanonicalInput expects. If this test breaks, the frontend page
// will generate tokens the backend rejects.
func TestFrontendCanonicalCompatibility(t *testing.T) {
	// This payload mirrors what deploy/frontend/pow.js builds.
	payload := TokenPayload{
		Version:    1,
		Mode:       "generic",
		Algorithm:  "sha256",
		Path:       "/ubuntu.iso",
		Timestamp:  1735689600,
		ExpiresAt:  1735691400,
		Difficulty: 22,
		Counter:    "0000000000000001",
		Salt:       "2025-demo-salt",
	}

	// Backend canonical
	backendCanonical := BuildCanonicalInput(&payload)

	// Frontend canonical (mirrors pow.js canonicalTemplate)
	ip := ""
	if payload.Mode == "ip_bound" {
		ip = payload.IP
	}
	frontendCanonical := "mirrors-pow-v1\n" +
		"mode=" + payload.Mode + "\n" +
		"ip=" + ip + "\n" +
		"path=" + payload.Path + "\n" +
		"ts=" + itoa64(payload.Timestamp) + "\n" +
		"exp=" + itoa64(payload.ExpiresAt) + "\n" +
		"difficulty=" + itoa64(int64(payload.Difficulty)) + "\n" +
		"cnt=" + payload.Counter + "\n" +
		"salt=" + payload.Salt + "\n"

	assert.Equal(t, backendCanonical, frontendCanonical,
		"frontend canonical must match backend canonical exactly")
}

// TestFrontendTokenEncoding verifies that the base64url token encoding
// used by pow.js (no padding) can be decoded by the backend's DecodeToken.
func TestFrontendTokenEncoding(t *testing.T) {
	payload := TokenPayload{
		Version:    1,
		Mode:       "generic",
		Algorithm:  "sha256",
		Path:       "/ubuntu.iso",
		Timestamp:  1735689600,
		ExpiresAt:  1735691400,
		Difficulty: 22,
		Counter:    "0000000000000001",
		Salt:       "2025-demo-salt",
	}

	// Frontend encoding: JSON -> base64url no padding
	jsonBytes, _ := json.Marshal(payload)
	frontendToken := base64.RawURLEncoding.EncodeToString(jsonBytes)

	// Backend decode
	decoded, err := DecodeToken(frontendToken)
	require.NoError(t, err)
	assert.Equal(t, payload.Mode, decoded.Mode)
	assert.Equal(t, payload.Path, decoded.Path)
	assert.Equal(t, payload.Difficulty, decoded.Difficulty)
	assert.Equal(t, payload.Counter, decoded.Counter)
}

// TestFrontendCanonicalIPBound verifies the ip_bound canonical has the
// IP field populated, matching pow.js behavior.
func TestFrontendCanonicalIPBound(t *testing.T) {
	payload := TokenPayload{
		Version:    1,
		Mode:       "ip_bound",
		Algorithm:  "sha256",
		IP:         "203.0.113.10",
		Path:       "/ubuntu.iso",
		Timestamp:  1735689600,
		ExpiresAt:  1735776000,
		Difficulty: 22,
		Counter:    "0000000000000001",
		Salt:       "2025-demo-salt",
	}

	backendCanonical := BuildCanonicalInput(&payload)
	assert.Contains(t, backendCanonical, "ip=203.0.113.10\n")
	assert.True(t, strings.HasSuffix(backendCanonical, "salt=2025-demo-salt\n"))
}

// itoa64 is a tiny int->string helper to avoid importing strconv.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
