package auth

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/pow"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

// verifyPoWOnly runs the PoW-only flow: the fallback when risk control is
// disabled, and the implementation that REQUIRE_POW conceptually defers to.
func (s *Service) verifyPoWOnly(ctx context.Context, req AuthRequest, tokenRaw, sign string, payload *pow.TokenPayload, powStatus string) AuthResult {
	if tokenRaw == "" || sign == "" {
		return s.maybeDryRun(ctx, deny(ReasonMissingTokenOrSign))
	}
	if len(tokenRaw) > s.cfg.Pow.MaxTokenLength {
		return s.maybeDryRun(ctx, deny(ReasonTokenTooLong))
	}
	if len(sign) > s.cfg.Pow.MaxSignLength {
		return s.maybeDryRun(ctx, deny(ReasonSignTooLong))
	}
	if payload == nil {
		return s.maybeDryRun(ctx, deny(ReasonMalformedToken))
	}

	mode := payload.Mode
	mc, ok := s.modeConfig(mode)
	if !ok {
		return s.maybeDryRun(ctx, denyMode(ReasonUnsupportedMode, mode))
	}
	if !mc.enabled {
		return s.maybeDryRun(ctx, denyMode(ReasonModeDisabled, mode))
	}

	// Full field validation: version, algorithm, path format, IP rules,
	// counter charset, difficulty range, salt whitelist. This runs in
	// classifyPoW too, so both paths enforce the same rules.
	if err := pow.ValidatePayload(payload, &mc.opts); err != nil {
		return s.maybeDryRun(ctx, denyMode(reasonFromValidationError(err), mode))
	}

	if payload.Path != req.OriginalURI {
		return s.maybeDryRun(ctx, denyMode(ReasonPathMismatch, mode))
	}

	now := s.clock.Now().Unix()
	if reason, ok := s.checkTime(payload, mc.maxTTL, now); !ok {
		return s.maybeDryRun(ctx, denyMode(reason, mode))
	}

	if reason, ok := checkSignAndDifficulty(payload, sign); !ok {
		return s.maybeDryRun(ctx, denyMode(reason, mode))
	}

	return s.finalizeByMode(ctx, req, payload, tokenRaw, sign, mode, now)
}

// checkSignAndDifficulty runs the three sign/difficulty checks shared by
// verifyPoWOnly and classifyPoW: hex format, SHA-256 equality, and
// leading-zero-bit difficulty. Returns ("", true) on success, or the
// failure reason and false on failure.
func checkSignAndDifficulty(p *pow.TokenPayload, sign string) (string, bool) {
	if !isValidSignHex(sign) {
		return ReasonInvalidSignFormat, false
	}
	if !pow.CompareSign(pow.ComputeSign(p), sign) {
		return ReasonSignMismatch, false
	}
	hash := pow.HashCanonical(pow.BuildCanonicalInput(p))
	if !pow.HasLeadingZeroBits32(hash, p.Difficulty) {
		return ReasonDifficultyNotMet, false
	}
	return "", true
}

// checkTime enforces the runtime time-based checks that ValidatePayload
// can't do (it doesn't know the current time or per-mode max TTL).
// Returns ("", true) on success, or the failure reason and false.
func (s *Service) checkTime(p *pow.TokenPayload, maxTTL int, now int64) (string, bool) {
	if p.ExpiresAt <= now {
		return ReasonExpired, false
	}
	if maxTTL > 0 && p.ExpiresAt-p.Timestamp > int64(maxTTL) {
		return ReasonTTLTooLong, false
	}
	if p.Timestamp > now+60 {
		return ReasonTimestampFromFuture, false
	}
	return "", true
}

func (s *Service) finalizeByMode(ctx context.Context, req AuthRequest, payload *pow.TokenPayload, tokenRaw, sign, mode string, now int64) AuthResult {
	switch mode {
	case "ip_bound":
		return s.finalizeIPBound(ctx, payload, req, tokenRaw, sign, mode)
	case "generic":
		return s.finalizeGeneric(ctx, payload, req, tokenRaw, sign, mode, now)
	}
	return s.maybeDryRun(ctx, denyMode(ReasonUnsupportedMode, mode))
}

func (s *Service) finalizeIPBound(ctx context.Context, p *pow.TokenPayload, req AuthRequest, tokenRaw, sign, mode string) AuthResult {
	if p.IP == "" {
		return s.maybeDryRun(ctx, denyMode(ReasonIPMissing, mode))
	}
	// An absent X-Real-IP means Nginx is not forwarding it. Failing this as
	// ip_mismatch would blame the client for a server misconfiguration and
	// make every ip_bound token look forged, so surface it as a 500 with a
	// distinct reason instead.
	if req.RealIP == "" {
		s.logger.Error(ctx, "X-Real-IP is empty; ip_bound tokens cannot be verified. "+
			"Check that Nginx sets proxy_set_header X-Real-IP on the auth_request location",
			logging.String("path", req.OriginalURI))
		return denyStatus(500, ReasonMissingRealIP, mode)
	}
	if !sameIP(p.IP, req.RealIP) {
		return s.maybeDryRun(ctx, denyMode(ReasonIPMismatch, mode))
	}
	res := allow(ReasonIPBoundValid, mode)
	res.SignID = pow.ComputeSignID(p, sign, mode)
	return res
}

func (s *Service) finalizeGeneric(ctx context.Context, p *pow.TokenPayload, req AuthRequest, tokenRaw, sign, mode string, now int64) AuthResult {
	signID := pow.ComputeSignID(p, sign, mode)
	if s.usageStore == nil {
		return s.maybeDryRun(ctx, withSignID(denyStatus(500, ReasonStorageError, mode), signID))
	}
	skipConsume := req.OriginalMethod == "HEAD" && !s.cfg.Pow.Modes.Generic.CountHeadRequest
	grace := 0
	if s.cfg.Cleanup.ExpiredGracePeriod > 0 {
		grace = int(s.cfg.Cleanup.ExpiredGracePeriod.Seconds())
	}
	cr, err := s.usageStore.Consume(ctx, storage.ConsumeInput{
		ID:           signID,
		Mode:         mode,
		Path:         p.Path,
		Sign:         sign,
		TokenHash:    pow.HashToken(tokenRaw),
		ExpiresAt:    p.ExpiresAt,
		MaxUses:      s.cfg.Pow.Modes.Generic.MaxUses,
		IP:           req.RealIP,
		UserAgent:    req.UserAgent,
		NowUnix:      now,
		GraceSeconds: grace,
		SkipConsume:  skipConsume,
	})
	if err != nil {
		return s.maybeDryRun(ctx, withSignID(denyStatus(500, ReasonStorageError, mode), signID))
	}
	if !cr.Allowed {
		res := withSignID(denyMode(ReasonUsedUp, mode), signID)
		res.Uses = cr.Uses
		res.MaxUses = cr.MaxUses
		return s.maybeDryRun(ctx, res)
	}
	res := allow(ReasonGenericValid, mode)
	res.SignID = signID
	res.Uses = cr.Uses
	res.MaxUses = cr.MaxUses
	return res
}

// classifyPoW does a side-effect-free classification for the risk engine's
// pre-evaluation. It returns (payload, pow_status, pow_mode) where
// pow_status is one of: missing, valid, invalid, expired, unverifiable.
//
// "unverifiable" means the token itself is well-formed but a required
// check could not be performed - currently only an ip_bound token when
// X-Real-IP is absent. It must never be treated as "valid": the
// REQUIRE_POW target consumes this status directly and would otherwise
// admit a token bound to somebody else's address.
func (s *Service) classifyPoW(ctx context.Context, tokenRaw, sign, path, realIP string) (*pow.TokenPayload, string, string) {
	if len(tokenRaw) > s.cfg.Pow.MaxTokenLength || len(sign) > s.cfg.Pow.MaxSignLength {
		return nil, "invalid", ""
	}
	payload, err := pow.DecodeToken(tokenRaw)
	if err != nil {
		return nil, "invalid", ""
	}
	mode := payload.Mode
	mc, ok := s.modeConfig(mode)
	if !ok {
		return payload, "invalid", mode
	}
	if err := pow.ValidatePayload(payload, &mc.opts); err != nil {
		return payload, "invalid", mode
	}
	if payload.Path != path {
		return payload, "invalid", mode
	}
	now := s.clock.Now().Unix()
	if payload.ExpiresAt <= now {
		return payload, "expired", mode
	}
	if _, ok := checkSignAndDifficulty(payload, sign); !ok {
		return payload, "invalid", mode
	}
	if mode == "ip_bound" {
		// An absent X-Real-IP is a proxy misconfiguration, not a forged
		// token, so this is deliberately distinct from "invalid" - but it
		// is emphatically not "valid" either, since the binding this mode
		// exists to enforce cannot be checked.
		if realIP == "" {
			return payload, "unverifiable", mode
		}
		if !sameIP(payload.IP, realIP) {
			return payload, "invalid", mode
		}
	}
	return payload, "valid", mode
}

// modeConfig bundles per-mode runtime config so the auth code doesn't
// scatter "if mode == ip_bound" switches across helper functions.
type modeConfig struct {
	enabled bool
	maxTTL  int
	opts    pow.ValidatorOptions
}

func (s *Service) modeConfig(mode string) (modeConfig, bool) {
	switch mode {
	case "ip_bound":
		return modeConfig{
			enabled: s.cfg.Pow.Modes.IPBound.Enabled,
			maxTTL:  s.cfg.Pow.Modes.IPBound.MaxTTLSeconds,
			opts:    s.ipBoundOpts,
		}, true
	case "generic":
		return modeConfig{
			enabled: s.cfg.Pow.Modes.Generic.Enabled,
			maxTTL:  s.cfg.Pow.Modes.Generic.MaxTTLSeconds,
			opts:    s.genericOpts,
		}, true
	}
	return modeConfig{}, false
}

// reasonFromValidationError maps a pow.ValidatePayload error to the
// X-Pow-Error reason string. Unknown errors fall back to malformed_token.
func reasonFromValidationError(err error) string {
	switch {
	case isErr(err, pow.ErrUnsupportedVersion):
		return ReasonUnsupportedVersion
	case isErr(err, pow.ErrUnsupportedMode):
		return ReasonUnsupportedMode
	case isErr(err, pow.ErrUnsupportedAlgorithm):
		return ReasonUnsupportedAlgorithm
	case isErr(err, pow.ErrPathInvalid), isErr(err, pow.ErrPathTooLong):
		return ReasonMalformedToken
	case isErr(err, pow.ErrIPMissing):
		return ReasonIPMissing
	case isErr(err, pow.ErrIPInvalid):
		return ReasonInvalidIP
	case isErr(err, pow.ErrIPForbidden):
		return ReasonIPForbidden
	case isErr(err, pow.ErrCounterInvalid):
		return ReasonInvalidCounter
	case isErr(err, pow.ErrDifficultyInvalid):
		return ReasonDifficultyTooLow
	case isErr(err, pow.ErrSaltInvalid):
		return ReasonInvalidSalt
	case isErr(err, pow.ErrTimestampInvalid), isErr(err, pow.ErrExpiryInvalid):
		return ReasonMalformedToken
	}
	return ReasonMalformedToken
}

func isErr(err, target error) bool { return errors.Is(err, target) }

func (s *Service) extractTokenAndSign(args string) (string, string) {
	if args == "" {
		return "", ""
	}
	values, err := url.ParseQuery(args)
	if err != nil {
		return "", ""
	}
	return values.Get(s.cfg.Pow.TokenParam), values.Get(s.cfg.Pow.SignParam)
}

func sameIP(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	na, errA := netip.ParseAddr(a)
	nb, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return false
	}
	return na.Unmap() == nb.Unmap()
}

func isValidSignHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// isRangeRequest reports whether the request is a Range request.
//
// Nginx's auth_request subrequest does NOT forward the Range header by
// default; when configured to forward it as X-Original-Range, we check
// it here. We also fall back to checking the method (HEAD) and query
// string markers.
func isRangeRequest(args, method, rangeHeader string) bool {
	if strings.EqualFold(method, "HEAD") {
		return true
	}
	if rangeHeader != "" {
		return true
	}
	if strings.Contains(strings.ToLower(args), "range=") {
		return true
	}
	return false
}

// toAuthTrace copies risk.TraceStep into auth.RiskTraceStep so the
// transport layer doesn't need to import internal/risk.
func toAuthTrace(in []risk.TraceStep) []RiskTraceStep {
	if len(in) == 0 {
		return nil
	}
	out := make([]RiskTraceStep, len(in))
	for i, step := range in {
		out[i] = RiskTraceStep{
			Chain: step.Chain, Rule: step.Rule, Matched: step.Matched,
			Target: step.Target, JumpTo: step.JumpTo,
		}
	}
	return out
}

// withSignID attaches a sign id to a result. Used in the generic flow
// where the deny needs to carry the sign id for diagnostics.
func withSignID(r AuthResult, signID string) AuthResult {
	r.SignID = signID
	return r
}
