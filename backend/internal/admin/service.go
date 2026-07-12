// admin uses an RPC-style API (system.ping, config.validate, etc.) rather
// than RESTful resource CRUD, because the operations are verbs not nouns
// and the consumer is a single front-end, not a generic REST client.
package admin

import (
	"context"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version"
)

type Service struct {
	cfg         *config.Config
	riskEngine  *risk.Engine
	auditLog    AuditLogger
	validator   Validator
}

type Options struct {
	Config    *config.Config
	RiskEngine *risk.Engine
	AuditLog  AuditLogger
	Validator Validator
}

func New(opts Options) (*Service, error) {
	s := &Service{
		cfg:        opts.Config,
		riskEngine: opts.RiskEngine,
		auditLog:   opts.AuditLog,
		validator:  opts.Validator,
	}
	if s.auditLog == nil {
		s.auditLog = NopAuditLogger{}
	}
	if s.validator == nil {
		s.validator = DefaultValidator{}
	}
	return s, nil
}

func (s *Service) Ping(ctx context.Context, _ PingRequest) (PingResponse, error) {
	return PingResponse{OK: true}, nil
}

func (s *Service) SystemInfo(_ context.Context, _ SystemInfoRequest) (SystemInfoResponse, error) {
	info := version.Get()
	return SystemInfoResponse{
		Version:    info.Version,
		Commit:     info.Commit,
		BuildTime:  info.BuildTime,
		GoVersion:  info.GoVersion,
	}, nil
}

func (s *Service) ConfigValidate(_ context.Context, req ConfigValidateRequest) (ConfigValidateResponse, error) {
	problems, err := s.validator.ValidateConfig(req.ConfigYAML)
	if err != nil {
		return ConfigValidateResponse{OK: false, Error: err.Error()}, nil
	}
	return ConfigValidateResponse{OK: len(problems) == 0, Problems: problems}, nil
}

func (s *Service) RulePreview(ctx context.Context, req RulePreviewRequest) (RulePreviewResponse, error) {
	if s.riskEngine == nil {
		return RulePreviewResponse{OK: false, Error: "risk engine is not enabled"}, nil
	}
	rctx := &risk.RequestContext{
		Path:           req.Request.Path,
		Method:         req.Request.Method,
		IP:             req.Request.IP,
		UserAgent:      req.Request.UserAgent,
		PowStatus:      req.Request.PowStatus,
		PowMode:        req.Request.PowMode,
		IsProtected:    req.Request.IsProtected,
		IsRangeRequest: req.Request.IsRangeRequest,
	}
	result, err := s.riskEngine.Evaluate(ctx, rctx)
	if err != nil {
		return RulePreviewResponse{OK: false, Error: err.Error()}, nil
	}
	trace := make([]TraceStepDTO, 0, len(result.Trace))
	for _, step := range result.Trace {
		trace = append(trace, TraceStepDTO{
			Chain: step.Chain, Rule: step.Rule, Matched: step.Matched,
			Target: step.Target, JumpTo: step.JumpTo,
		})
	}
	return RulePreviewResponse{
		OK: true,
		Decision: DecisionDTO{
			Target:     result.Decision.Target,
			StatusCode: result.Decision.StatusCode,
			LimitRate:  result.Decision.LimitRate,
			Reason:     result.Decision.Reason,
			Chain:      result.Decision.Chain,
			RuleName:   result.Decision.RuleName,
		},
		Trace: trace,
	}, nil
}

// RuleReload is not implemented in v1; restart the service to pick up
// config changes.
func (s *Service) RuleReload(_ context.Context, _ RuleReloadRequest) (RuleReloadResponse, error) {
	return RuleReloadResponse{OK: false, Error: "rule.reload is not implemented in v1; restart the service to pick up config changes"}, nil
}
