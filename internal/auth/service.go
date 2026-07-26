package auth

import (
	"context"
	"errors"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/clock"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/matcher"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

type Service struct {
	cfg        *config.Config
	matcher    matcher.Matcher
	usageStore storage.UsageStore
	clock      clock.Clock
	logger     logging.Logger
	metrics    *metrics.Container
	riskEngine *risk.Engine
	counterReg *risk.CounterRegistry

	ipBoundOpts pow.ValidatorOptions
	genericOpts pow.ValidatorOptions

	// allowedSalts is derived from cfg.Pow.PublicSalt + AllowedPreviousSalts.
	allowedSalts []string
}

// Options bundles the constructor dependencies.
//
// Required: Config, Matcher.
// Conditionally required (detected from config at startup):
//   - UsageStore, when generic mode is enabled
//   - RiskEngine, when risk_control is enabled
//   - CounterReg, when risk_control counters are configured
//
// Optional (nil defaults to a sensible no-op):
//   - Clock nil -> real wall clock
//   - Logger nil -> Nop logger
//   - Metrics nil -> no metrics emitted
type Options struct {
	Config     *config.Config
	Matcher    matcher.Matcher
	UsageStore storage.UsageStore
	Clock      clock.Clock
	Logger     logging.Logger
	Metrics    *metrics.Container
	RiskEngine *risk.Engine
	CounterReg *risk.CounterRegistry
}

func New(opts Options) (*Service, error) {
	if opts.Config == nil {
		return nil, errors.New("auth: Config is required")
	}
	if opts.Matcher == nil {
		return nil, errors.New("auth: Matcher is required")
	}
	// generic mode needs a usage store; otherwise the first generic
	// request would 500 at runtime instead of failing fast at startup.
	if opts.Config.Pow.Modes.Generic.Enabled && opts.UsageStore == nil {
		return nil, errors.New("auth: UsageStore is required when generic mode is enabled")
	}
	// When risk control is on, the engine must be wired. A nil engine
	// would silently disable every rule.
	if opts.Config.RiskControl.Enabled && opts.RiskEngine == nil {
		return nil, errors.New("auth: RiskEngine is required when risk_control is enabled")
	}
	// Counter rules can't fire without a registry; fail fast so the
	// operator doesn't discover this in production.
	if opts.Config.RiskControl.Enabled && len(opts.Config.RiskControl.Counters) > 0 && opts.CounterReg == nil {
		return nil, errors.New("auth: CounterReg is required when risk_control counters are configured")
	}
	if opts.Clock == nil {
		opts.Clock = clock.New()
	}
	if opts.Logger == nil {
		opts.Logger = logging.NewNop()
	}

	s := &Service{
		cfg:        opts.Config,
		matcher:    opts.Matcher,
		usageStore: opts.UsageStore,
		clock:      opts.Clock,
		logger:     opts.Logger,
		metrics:    opts.Metrics,
		riskEngine: opts.RiskEngine,
		counterReg: opts.CounterReg,
	}

	s.allowedSalts = append(s.allowedSalts, opts.Config.Pow.AllowedPreviousSalts...)
	if opts.Config.Pow.PublicSalt != "" {
		s.allowedSalts = append(s.allowedSalts, opts.Config.Pow.PublicSalt)
	}

	s.ipBoundOpts = pow.ValidatorOptions{
		AllowedSalts:   s.allowedSalts,
		AllowEmptySalt: opts.Config.Pow.AllowEmptySalt,
		AllowedModes:   []string{"ip_bound"},
		RequireIP:      opts.Config.Pow.Modes.IPBound.RequireIP,
		MinDifficulty:  opts.Config.Pow.Modes.IPBound.MinDifficulty,
		MaxDifficulty:  opts.Config.Pow.Modes.IPBound.MaxDifficulty,
	}
	s.genericOpts = pow.ValidatorOptions{
		AllowedSalts:   s.allowedSalts,
		AllowEmptySalt: opts.Config.Pow.AllowEmptySalt,
		AllowedModes:   []string{"generic"},
		MinDifficulty:  opts.Config.Pow.Modes.Generic.MinDifficulty,
		MaxDifficulty:  opts.Config.Pow.Modes.Generic.MaxDifficulty,
	}

	return s, nil
}

// Verify runs the full PoW + risk flow for one request.
func (s *Service) Verify(ctx context.Context, req AuthRequest) AuthResult {
	vctx := verifyCtx{
		req:   req,
		start: s.clock.Now(),
	}
	vctx.logFields = []logging.Field{
		logging.String("path", req.OriginalURI),
		logging.String("ip", s.maybeHashIP(req.RealIP)),
		logging.String("method", req.OriginalMethod),
		logging.String("user_agent", req.UserAgent),
	}
	// NOTE: the latency histogram is observed inside recordResult, not in a
	// defer here, so that the "mode" label is populated. Every return path
	// below calls recordResult exactly once.

	if s.cfg.Pow.BypassAll {
		res := allowDecision(ReasonBypassAll, "", DecisionBypass)
		s.recordResult(vctx, res)
		return res
	}

	if req.OriginalURI == "" {
		res := denyStatus(500, ReasonMissingHeaders, "")
		s.recordResult(vctx, res)
		return res
	}

	protected := s.matcher.ShouldProtect(req.OriginalURI)
	tokenRaw, sign := s.extractTokenAndSign(req.OriginalArgs)

	riskReq := &risk.RequestContext{
		Path:           req.OriginalURI,
		Method:         req.OriginalMethod,
		Args:           req.OriginalArgs,
		IP:             req.RealIP,
		UserAgent:      req.UserAgent,
		HasToken:       tokenRaw != "",
		HasSign:        sign != "",
		IsProtected:    protected,
		IsRangeRequest: isRangeRequest(req.OriginalArgs, req.OriginalMethod, req.OriginalRange),
	}

	// Light-weight PoW classification: missing / valid / invalid / expired.
	// We do NOT increment usage here; that happens only when the risk
	// engine decides to allow the request via PoW.
	powStatus := "missing"
	var payload *pow.TokenPayload
	if tokenRaw != "" && sign != "" {
		var powMode string
		payload, powStatus, powMode = s.classifyPoW(ctx, tokenRaw, sign, req.OriginalURI, req.RealIP)
		riskReq.PowStatus = powStatus
		riskReq.PowMode = powMode
	}
	vctx.payload = payload

	if res, ok := s.runRiskEngine(ctx, vctx, riskReq, powStatus); ok {
		return res
	}

	// No risk engine (or it returned REQUIRE_POW-style fallthrough):
	// run the PoW-only flow. Non-protected paths bypass PoW entirely
	// when risk control is off.
	if s.riskEngine == nil && !protected {
		res := allowDecision(ReasonNotProtected, "", DecisionNotProtected)
		s.recordResult(vctx, res)
		return res
	}
	res := s.verifyPoWOnly(ctx, req, tokenRaw, sign, payload, powStatus)
	s.recordResult(vctx, res)
	return res
}

// runRiskEngine evaluates the risk chain and returns (result, handled).
// When handled is false the caller should fall through to verifyPoWOnly.
func (s *Service) runRiskEngine(ctx context.Context, vctx verifyCtx, riskReq *risk.RequestContext, powStatus string) (AuthResult, bool) {
	if s.riskEngine == nil {
		return AuthResult{}, false
	}

	riskReq.Counters = s.lookupCounterResolver(ctx, riskReq)
	result, err := s.riskEngine.Evaluate(ctx, riskReq)
	if err != nil {
		s.logger.Warn(ctx, "risk engine evaluate failed", logging.Err(err))
		return AuthResult{}, false
	}

	// Bump counters whose "when" matches, after evaluation.
	if s.counterReg != nil {
		for _, e := range s.counterReg.IncrementForRequest(ctx, riskReq) {
			s.logger.Warn(ctx, "counter incr failed", logging.Err(e))
		}
	}

	dec := result.Decision
	if s.metrics != nil {
		s.metrics.RiskDecisionTotal.
			WithLabelValues(dec.Target, dec.Reason).
			Inc()
	}
	trace := toAuthTrace(result.Trace)
	switch dec.Target {
	case risk.TargetACCEPT, risk.TargetRATELIMIT:
		res := allow(reasonForAccept(dec.Reason), riskReq.PowMode)
		res.LimitRate = dec.LimitRate
		res.RiskChain = dec.Chain
		res.RiskRule = dec.RuleName
		res.RiskTrace = trace
		res.RiskMarks = dec.Marks
		res.Decision = s.decideForAllow(res)
		s.recordResult(vctx, res)
		return res, true

	case risk.TargetREJECT:
		reason := dec.Reason
		if reason == "" {
			reason = ReasonRiskReject
		}
		res := denyMode(reason, riskReq.PowMode)
		res.RiskChain = dec.Chain
		res.RiskRule = dec.RuleName
		res.RiskTrace = trace
		res.RiskMarks = dec.Marks
		s.recordResult(vctx, res)
		return res, true

	case risk.TargetTOOMANY:
		reason := dec.Reason
		if reason == "" {
			reason = ReasonRateLimited
		}
		res := denyStatus(429, reason, riskReq.PowMode)
		res.RiskChain = dec.Chain
		res.RiskRule = dec.RuleName
		res.RiskTrace = trace
		res.RiskMarks = dec.Marks
		s.recordResult(vctx, res)
		return res, true

	case risk.TargetREQUIREPOW:
		var res AuthResult
		switch powStatus {
		case "valid":
			res = allow(ReasonRequirePowPass, riskReq.PowMode)
		case "missing":
			res = deny(ReasonMissingTokenOrSign)
		case "unverifiable":
			// The token could not be checked because X-Real-IP is absent.
			// Fail closed with a server error rather than admitting it:
			// this path never reaches finalizeIPBound, so there is no
			// later gate that would catch it.
			s.logger.Error(ctx, "X-Real-IP is empty; ip_bound token cannot be verified. "+
				"Check that Nginx sets proxy_set_header X-Real-IP on the auth_request location",
				logging.String("path", riskReq.Path))
			res = denyStatus(500, ReasonMissingRealIP, riskReq.PowMode)
		default:
			res = denyMode(powStatusToReason(powStatus), riskReq.PowMode)
		}
		s.recordResult(vctx, res)
		return res, true
	}

	return AuthResult{}, false
}

// maybeDryRun rewrites a deny into an allow when dry-run mode is enabled.
// The original reason is preserved in DryRunOriginalError for visibility.
func (s *Service) maybeDryRun(_ context.Context, res AuthResult) AuthResult {
	if !s.cfg.Pow.DryRun || res.Allowed {
		return res
	}
	orig := res.Reason
	res.Allowed = true
	res.HTTPStatus = 200
	res.Reason = ReasonDryRunAllow
	res.DryRunOriginalError = orig
	res.ErrorHeader = ""
	res.Decision = DecisionDryRun
	return res
}
