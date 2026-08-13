package admin

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

const maxBlockReasonRunes = 256

func (s *Service) RiskBlocksList(ctx context.Context, _ RiskBlocksListRequest) (RiskBlocksListResponse, error) {
	return s.PendingList(ctx, PendingListRequest{})
}

func (s *Service) RiskBlocksAdd(_ context.Context, req RiskBlockAddRequest) (RiskBlockMutationResponse, error) {
	if err := s.checkIPBlockMutationAccess(); err != nil {
		return RiskBlockMutationResponse{}, err
	}
	ip, err := confirmedIP(req.IP, req.ConfirmIP)
	if err != nil {
		return RiskBlockMutationResponse{}, err
	}
	reason, err := validateBlockReason(req.Reason)
	if err != nil {
		return RiskBlockMutationResponse{}, err
	}
	ttl, err := s.blockTTL(req.TTLSeconds)
	if err != nil {
		return RiskBlockMutationResponse{}, err
	}
	actor := strings.TrimSpace(req.Actor)
	if actor == "" {
		return RiskBlockMutationResponse{}, ValidationError("authenticated actor is required")
	}

	result, err := s.ipBlocks.Block(ip, risk.BlockInput{TTL: ttl, Reason: reason, Actor: actor})
	if err != nil {
		return RiskBlockMutationResponse{}, mapBlockControllerError(err)
	}
	return RiskBlockMutationResponse{
		Scope:   "instance",
		Changed: result.Changed,
		Entry:   pendingEntryDTO(result.State),
	}, nil
}

func (s *Service) RiskBlocksUnblock(_ context.Context, req RiskBlockUnblockRequest) (RiskBlockMutationResponse, error) {
	if err := s.checkIPBlockMutationAccess(); err != nil {
		return RiskBlockMutationResponse{}, err
	}
	ip, err := confirmedIP(req.IP, req.ConfirmIP)
	if err != nil {
		return RiskBlockMutationResponse{}, err
	}
	if strings.TrimSpace(req.Actor) == "" {
		return RiskBlockMutationResponse{}, ValidationError("authenticated actor is required")
	}

	result, err := s.ipBlocks.Unblock(ip)
	if err != nil {
		return RiskBlockMutationResponse{}, mapBlockControllerError(err)
	}
	return RiskBlockMutationResponse{
		Scope:   "instance",
		Changed: result.Changed,
		Entry:   pendingEntryDTO(result.State),
	}, nil
}

func (s *Service) checkIPBlockMutationAccess() error {
	if s.cfg == nil || !s.cfg.Admin.MutationsEnabled {
		return MutationsDisabledError()
	}
	if s.cfg.Admin.Auth.Type != "token" && s.cfg.Admin.Auth.Type != "basic" {
		return MutationAuthRequiredError()
	}
	if !s.cfg.Admin.IPBlock.Enabled {
		return IPBlockDisabledError()
	}
	if s.ipBlocks == nil {
		return BlockStoreUnavailableError()
	}
	return nil
}

func confirmedIP(raw, confirmation string) (string, error) {
	ip, err := risk.CanonicalIP(raw)
	if err != nil {
		return "", ValidationError("ip must be one valid IP address")
	}
	confirmed, err := risk.CanonicalIP(confirmation)
	if err != nil || confirmed != ip {
		return "", ValidationError("confirm_ip must match ip")
	}
	return ip, nil
}

func validateBlockReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	if reason == "" {
		return "", ValidationError("reason is required")
	}
	if !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > maxBlockReasonRunes {
		return "", ValidationError("reason must be at most 256 characters")
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return "", ValidationError("reason must not contain control characters")
		}
	}
	return reason, nil
}

func (s *Service) blockTTL(seconds int64) (time.Duration, error) {
	if s.cfg == nil {
		return 0, MutationsDisabledError()
	}
	if seconds == 0 {
		return s.cfg.Admin.IPBlock.DefaultTTL, nil
	}
	if seconds < 0 {
		return 0, ValidationError("ttl_seconds must be greater than zero")
	}
	maxSeconds := int64(s.cfg.Admin.IPBlock.MaxTTL / time.Second)
	if maxSeconds < 1 || seconds > maxSeconds {
		return 0, ValidationError("ttl_seconds exceeds the configured maximum")
	}
	return time.Duration(seconds) * time.Second, nil
}

func mapBlockControllerError(err error) error {
	switch {
	case errors.Is(err, risk.ErrInvalidBlockIP), errors.Is(err, risk.ErrInvalidBlock):
		return ValidationError("invalid IP block request")
	case errors.Is(err, risk.ErrBlockerClosed):
		return BlockStoreUnavailableError()
	default:
		return BlockStoreUnavailableError()
	}
}
