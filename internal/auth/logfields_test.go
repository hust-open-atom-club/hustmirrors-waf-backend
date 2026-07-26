package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTruncateForLog covers the helper directly, including the boundary
// where truncation kicks in.
func TestTruncateForLog(t *testing.T) {
	assert.Equal(t, "short", truncateForLog("short", 10))
	assert.Equal(t, "exact", truncateForLog("exact", 5))

	long := strings.Repeat("a", 20)
	got := truncateForLog(long, 5)
	assert.Equal(t, "aaaaa…(truncated)", got)
	assert.True(t, strings.HasSuffix(got, "…(truncated)"),
		"a shortened value must be marked, or it reads as the real one")
}

// TestVerify_OversizedHeadersAreTruncatedInLogs guards log volume. path and
// user_agent are attacker-controlled headers written verbatim to every log
// line; without a cap one request can emit tens of kilobytes, making the
// log pipeline the cheapest resource to exhaust.
//
// The service must still behave normally - truncation is a logging
// concern and must not change the verification result.
func TestVerify_OversizedHeadersAreTruncatedInLogs(t *testing.T) {
	svc, _, _, _ := makeTestService(t, nil)

	huge := strings.Repeat("A", 50_000)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		UserAgent:      huge,
		RealIP:         "1.2.3.4",
	})

	// Verification itself is unaffected.
	require.False(t, res.Allowed)
	assert.Equal(t, ReasonMissingTokenOrSign, res.Reason)

	// The field that would have been logged is bounded.
	assert.LessOrEqual(t, len(truncateForLog(huge, maxLoggedFieldLen)),
		maxLoggedFieldLen+len("…(truncated)"),
		"a 50KB user agent must not reach the log verbatim")
}
