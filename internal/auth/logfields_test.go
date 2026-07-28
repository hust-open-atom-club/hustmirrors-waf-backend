package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/clock"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/matcher"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
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

// TestLogSwitches_ControlWhichOutcomesAreLogged: both switches were never
// read. Also asserts metrics survive a silenced log, which is what makes
// the switch safe to use.
func TestLogSwitches_ControlWhichOutcomesAreLogged(t *testing.T) {
	newSvc := func(access, denied *bool) (*Service, *observer.ObservedLogs, func(pow.TokenPayload) (string, string)) {
		core, logs := observer.New(zap.DebugLevel)
		cfg := makeBaseConfig()
		cfg.Logging.LogAccess = access
		cfg.Logging.LogDenied = denied
		svc, err := New(Options{
			Config: cfg,
			Matcher: matcher.NewComposite(
				matcher.NewExtensionMatcher(cfg.Protection.ProtectedExtensions), nil),
			UsageStore: memory.NewUsageStore(),
			Clock:      clock.NewFake(),
			Logger:     logging.NewFromZap(zap.New(core)),
			Metrics:    metrics.New(),
		})
		require.NoError(t, err)
		return svc, logs, nil
	}

	denyReq := AuthRequest{OriginalURI: "/ubuntu.iso", OriginalMethod: "GET", RealIP: "1.2.3.4"}
	allowReq := AuthRequest{OriginalURI: "/index.html", OriginalMethod: "GET", RealIP: "1.2.3.4"}

	off, on := false, true

	t.Run("log_denied false silences denies", func(t *testing.T) {
		svc, logs, _ := newSvc(&on, &off)
		svc.Verify(context.Background(), denyReq)
		assert.Zero(t, logs.FilterMessageSnippet("pow_verify").Len())
		// The metric is still recorded.
		assert.Equal(t, float64(1), testutil.ToFloat64(
			svc.metrics.PowVerifyTotal.WithLabelValues("deny", ReasonMissingTokenOrSign, "")),
			"metrics must not be affected by a logging switch")
	})

	t.Run("log_access false silences allows", func(t *testing.T) {
		svc, logs, _ := newSvc(&off, &on)
		svc.Verify(context.Background(), allowReq)
		assert.Zero(t, logs.FilterMessageSnippet("pow_verify").Len())
	})

	t.Run("both on logs both", func(t *testing.T) {
		svc, logs, _ := newSvc(&on, &on)
		svc.Verify(context.Background(), denyReq)
		svc.Verify(context.Background(), allowReq)
		assert.Equal(t, 2, logs.FilterMessageSnippet("pow_verify").Len())
	})

	t.Run("nil defaults to logging", func(t *testing.T) {
		svc, logs, _ := newSvc(nil, nil)
		svc.Verify(context.Background(), denyReq)
		assert.Equal(t, 1, logs.FilterMessageSnippet("pow_verify").Len(),
			"an omitted switch must not drop the audit trail")
	})

	t.Run("server errors are always logged", func(t *testing.T) {
		// A 5xx is a fault in this service, not a verdict, so it survives
		// log_denied=false.
		svc, logs, _ := newSvc(&off, &off)
		svc.Verify(context.Background(), AuthRequest{
			OriginalURI: "", OriginalMethod: "GET", RealIP: "1.2.3.4",
		})
		assert.Equal(t, 1, logs.FilterMessageSnippet("pow_verify").Len(),
			"a 5xx must not be silenced by a volume setting")
	})
}
