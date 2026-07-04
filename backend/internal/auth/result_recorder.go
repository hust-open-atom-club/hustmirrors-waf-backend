package auth

import (
	"context"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

// verifyCtx bundles per-request state that recordResult needs.
type verifyCtx struct {
	req       AuthRequest
	payload   *pow.TokenPayload
	start     time.Time
	logFields []logging.Field
}

// recordResult writes the metrics counter + structured log line for one
// verification result.
func (s *Service) recordResult(vctx verifyCtx, res AuthResult) {
	if s.metrics != nil {
		s.metrics.PowVerifyTotal.WithLabelValues(
			statusBucket(res.Allowed),
			res.Reason,
			res.Mode,
		).Inc()
	}
	lvl := "info"
	if !res.Allowed {
		if res.HTTPStatus >= 500 {
			lvl = "error"
		} else {
			lvl = "warn"
		}
	}
	elapsedMs := time.Since(vctx.start).Milliseconds()
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
