package admin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/auth"
)

// MaxOverrideTTL caps emergency-switch overrides. A bypass left on for hours
// silently defeats the whole WAF, so each override must re-arm itself.
const MaxOverrideTTL = 2 * time.Hour

// OverrideSource is the auth service's runtime-override surface. The auth
// service implements it; admin depends on the interface, not the concrete
// type.
type OverrideSource interface {
	SetOverride(key auth.OverrideKey, value bool, reason string, ttl time.Duration)
	ClearOverride(key auth.OverrideKey) bool
	OverrideSnapshot() []auth.OverrideState
}

func (s *Service) RuntimeStatus(_ context.Context, _ RuntimeStatusRequest) (RuntimeStatusResponse, error) {
	resp := RuntimeStatusResponse{
		Switches: []RuntimeSwitchDTO{
			{
				Key:           "bypass_all",
				ConfigValue:   s.cfg.Pow.BypassAll,
				MaxTTLSeconds: int(MaxOverrideTTL.Seconds()),
				Description:   "跳过 PoW 与风控直接放行（手动封禁 IP 仍生效）",
			},
			{
				Key:           "dry_run",
				ConfigValue:   s.cfg.Pow.DryRun,
				MaxTTLSeconds: int(MaxOverrideTTL.Seconds()),
				Description:   "照常验证但拒绝结果改写为放行，保留原始原因",
			},
		},
		Overrides: []RuntimeOverrideDTO{},
	}

	active := map[auth.OverrideKey]auth.OverrideState{}
	if s.overrides != nil {
		for _, st := range s.overrides.OverrideSnapshot() {
			active[st.Key] = st
			resp.Overrides = append(resp.Overrides, RuntimeOverrideDTO{
				Key:       string(st.Key),
				Value:     st.Value,
				Reason:    st.Reason,
				ExpiresAt: st.ExpiresAt,
			})
		}
	}
	for i := range resp.Switches {
		sw := &resp.Switches[i]
		sw.ActiveValue = sw.ConfigValue
		if st, ok := active[auth.OverrideKey(sw.Key)]; ok {
			sw.Overridden = true
			sw.ActiveValue = st.Value
			sw.Reason = st.Reason
		}
	}
	return resp, nil
}

func (s *Service) RuntimeOverrideSet(ctx context.Context, req RuntimeOverrideSetRequest) (RuntimeStatusResponse, error) {
	if err := s.checkRuntimeMutationAccess(); err != nil {
		return RuntimeStatusResponse{}, err
	}
	if s.overrides == nil {
		return RuntimeStatusResponse{}, ValidationError("runtime overrides are not wired on this instance")
	}
	key, err := parseOverrideKey(req.Key)
	if err != nil {
		return RuntimeStatusResponse{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return RuntimeStatusResponse{}, ValidationError("reason is required for runtime overrides")
	}
	if req.TTLSeconds <= 0 || time.Duration(req.TTLSeconds)*time.Second > MaxOverrideTTL {
		return RuntimeStatusResponse{}, ValidationError(fmt.Sprintf("ttl_seconds must be between 1 and %d", int(MaxOverrideTTL.Seconds())))
	}

	s.overrides.SetOverride(key, req.Value, reason, time.Duration(req.TTLSeconds)*time.Second)
	return s.RuntimeStatus(ctx, RuntimeStatusRequest{})
}

func (s *Service) RuntimeOverrideClear(ctx context.Context, req RuntimeOverrideClearRequest) (RuntimeStatusResponse, error) {
	if err := s.checkRuntimeMutationAccess(); err != nil {
		return RuntimeStatusResponse{}, err
	}
	key, err := parseOverrideKey(req.Key)
	if err != nil {
		return RuntimeStatusResponse{}, err
	}
	// Clear is idempotent: clearing an inactive override still succeeds.
	_ = s.overrides.ClearOverride(key)
	return s.RuntimeStatus(ctx, RuntimeStatusRequest{})
}

func parseOverrideKey(raw string) (auth.OverrideKey, error) {
	switch strings.TrimSpace(raw) {
	case "bypass_all":
		return auth.OverrideBypassAll, nil
	case "dry_run":
		return auth.OverrideDryRun, nil
	}
	return "", ValidationError("key must be bypass_all or dry_run")
}

func (s *Service) checkRuntimeMutationAccess() error {
	if s.cfg == nil || !s.cfg.Admin.MutationsEnabled {
		return MutationsDisabledError()
	}
	if s.cfg.Admin.Auth.Type != "token" && s.cfg.Admin.Auth.Type != "basic" {
		return MutationAuthRequiredError()
	}
	return nil
}
