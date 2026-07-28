package auth

import (
	"context"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

// maxLoggedFieldLen caps attacker-controlled strings in log lines.
// Not about injection (the JSON encoder escapes fine) but volume: path and
// user_agent are raw headers, and 1MB of them per request makes the log
// pipeline the cheapest thing to exhaust.
const maxLoggedFieldLen = 512

// truncateForLog marks what it shortens, so a clipped value isn't mistaken
// for the original when reading logs.
func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…(truncated)"
}

// verifyCtx bundles per-request state that recordResult needs.
type verifyCtx struct {
	req       AuthRequest
	payload   *pow.TokenPayload
	tokenRaw  string
	sign      string
	start     time.Time
	logFields []logging.Field

	// Populated when the risk-engine allow path charges the generic quota,
	// so the result can carry the same headers the PoW-only path emits.
	signID  string
	uses    int
	maxUses int
}

// recordResult writes the metrics counter + structured log line for one
// verification result.
//
// Every return path in Verify funnels through here, so this is also where
// the latency histogram is observed: doing it here (rather than in a defer
// at the top of Verify) means the "mode" label is already resolved.
func (s *Service) recordResult(vctx verifyCtx, res AuthResult) {
	elapsed := time.Since(vctx.start)
	if s.metrics != nil {
		s.metrics.PowVerifyTotal.WithLabelValues(
			statusBucket(res.Allowed),
			res.Reason,
			res.Mode,
		).Inc()
		s.metrics.PowVerifyLatencySeconds.
			WithLabelValues(res.Mode).
			Observe(elapsed.Seconds())
	}
	// Metrics above are unconditional, so silencing the log cannot blind
	// monitoring.
	if !s.shouldLogResult(res) {
		return
	}

	lvl := "info"
	if !res.Allowed {
		if res.HTTPStatus >= 500 {
			lvl = "error"
		} else {
			lvl = "warn"
		}
	}
	elapsedMs := elapsed.Milliseconds()
	all := append([]logging.Field{}, vctx.logFields...)
	all = append(all,
		logging.String("event", "pow_verify"),
		logging.Bool("allowed", res.Allowed),
		logging.Int("status", res.HTTPStatus),
		logging.String("reason", res.Reason),
		logging.String("mode", res.Mode),
		logging.String("decision", res.Decision),
		logging.Int64("elapsed_ms", elapsedMs),
	)
	if vctx.payload != nil {
		all = append(all, logging.Int("difficulty", vctx.payload.Difficulty))
		if vctx.payload.Mode == "ip_bound" && vctx.payload.IP != "" {
			all = append(all, logging.String("token_ip", s.maybeHashIP(vctx.payload.IP)))
		}
	}
	if res.SignID != "" {
		all = append(all, logging.String("sign_id", res.SignID))
	}
	if res.Uses > 0 || res.MaxUses > 0 {
		all = append(all, logging.Int("uses", res.Uses), logging.Int("max_uses", res.MaxUses))
	}
	if res.LimitRate != "" {
		all = append(all, logging.String("limit_rate", res.LimitRate))
	}
	if res.DryRunOriginalError != "" {
		all = append(all, logging.String("dry_run_original_error", res.DryRunOriginalError))
	}
	switch lvl {
	case "error":
		s.logger.Error(context.Background(), "pow_verify", all...)
	case "warn":
		s.logger.Warn(context.Background(), "pow_verify", all...)
	default:
		s.logger.Info(context.Background(), "pow_verify", all...)
	}
}

// shouldLogResult applies logging.log_access and log_denied. A 5xx is always
// logged: that is a fault here, not a verdict, and hiding it would mask
// outages. nil means absent, i.e. on.
func (s *Service) shouldLogResult(res AuthResult) bool {
	if res.HTTPStatus >= 500 {
		return true
	}
	if res.Allowed {
		return s.cfg.Logging.LogAccess == nil || *s.cfg.Logging.LogAccess
	}
	return s.cfg.Logging.LogDenied == nil || *s.cfg.Logging.LogDenied
}

func (s *Service) maybeHashIP(ip string) string {
	if ip == "" {
		return ""
	}
	if !s.cfg.Logging.HashIP {
		return ip
	}
	return logging.HashIP(ip, s.cfg.Logging.LogSalt)
}

func (s *Service) lookupCounterResolver(ctx context.Context, req *risk.RequestContext) risk.CounterResolver {
	if s.counterReg == nil {
		return risk.NoopCounterResolver
	}
	return s.counterReg.LookupResolver(ctx, req)
}
