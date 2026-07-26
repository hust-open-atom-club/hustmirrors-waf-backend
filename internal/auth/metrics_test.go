package auth

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/clock"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/matcher"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
)

// makeMetricsService mirrors makeTestService but hands back the metrics
// container so assertions can be made against it, and allows injecting a
// risk engine.
func makeMetricsService(t *testing.T, cfg *config.Config, engine *risk.Engine) (*Service, *metrics.Container) {
	t.Helper()
	if cfg == nil {
		cfg = makeBaseConfig()
	}
	m := metrics.New()
	svc, err := New(Options{
		Config: cfg,
		Matcher: matcher.NewComposite(
			matcher.NewExtensionMatcher(cfg.Protection.ProtectedExtensions), nil),
		UsageStore: memory.NewUsageStore(),
		Clock:      clock.NewFake(),
		Logger:     logging.NewNop(),
		Metrics:    m,
		RiskEngine: engine,
	})
	require.NoError(t, err)
	return svc, m
}

// histogramCountForMode returns the observation count recorded against a
// specific "mode" label value, or -1 when that label was never used.
func histogramCountForMode(t *testing.T, h *prometheus.HistogramVec, mode string) int {
	t.Helper()
	ch := make(chan prometheus.Metric, 32)
	h.Collect(ch)
	close(ch)
	for metric := range ch {
		var out dto.Metric
		require.NoError(t, metric.Write(&out))
		for _, lp := range out.GetLabel() {
			if lp.GetName() == "mode" && lp.GetValue() == mode {
				return int(out.GetHistogram().GetSampleCount())
			}
		}
	}
	return -1
}

// TestMetrics_LatencyCarriesModeLabel guards the regression where the
// histogram was observed from a defer registered before the mode was known,
// so every sample landed on the empty label and per-mode latency was lost.
func TestMetrics_LatencyCarriesModeLabel(t *testing.T) {
	svc, _, _, mint := makeTestService(t, nil)
	m := svc.metrics
	require.NotNil(t, m)

	payload := findValidCounterForDifficulty(t, pow.TokenPayload{
		Mode: "generic", Path: "/ubuntu.iso",
	}, 8)
	token, sign := mint(payload)
	res := svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		OriginalArgs:   "token=" + token + "&sign=" + sign,
		RealIP:         "1.2.3.4",
	})
	require.True(t, res.Allowed, "reason=%s", res.Reason)
	require.Equal(t, "generic", res.Mode)

	assert.Equal(t, 1, histogramCountForMode(t, m.PowVerifyLatencySeconds, "generic"),
		"latency sample must be attributed to mode=generic")
	assert.Equal(t, -1, histogramCountForMode(t, m.PowVerifyLatencySeconds, ""),
		"no sample may land on the empty mode label")
}

// TestMetrics_VerifyTotalIsEmitted covers the counter alongside the histogram.
func TestMetrics_VerifyTotalIsEmitted(t *testing.T) {
	svc, m := makeMetricsService(t, nil, nil)
	svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		RealIP:         "1.2.3.4",
	})
	assert.Equal(t, float64(1), testutil.ToFloat64(
		m.PowVerifyTotal.WithLabelValues("deny", ReasonMissingTokenOrSign, "")))
}

// TestMetrics_RiskDecisionIsEmitted proves risk_decision_total — previously
// defined but never incremented — now fires on every engine evaluation.
func TestMetrics_RiskDecisionIsEmitted(t *testing.T) {
	cfg := makeBaseConfig()
	cfg.RiskControl.Enabled = true

	// A chain with no rules falls through to its policy, which produces a
	// decision without needing risk's unexported matcher types.
	engine, err := risk.NewEngine(risk.ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: risk.Policy{Target: risk.TargetACCEPT, Reason: "test_accept"},
		},
	})
	require.NoError(t, err)

	svc, m := makeMetricsService(t, cfg, engine)
	svc.Verify(context.Background(), AuthRequest{
		OriginalURI:    "/ubuntu.iso",
		OriginalMethod: "GET",
		RealIP:         "1.2.3.4",
	})

	assert.Equal(t, float64(1), testutil.ToFloat64(
		m.RiskDecisionTotal.WithLabelValues(risk.TargetACCEPT, "test_accept")),
		"risk_decision_total must be incremented on every engine evaluation")
}
