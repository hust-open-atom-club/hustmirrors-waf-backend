package echo

import (
	"net/http"

	echov4 "github.com/labstack/echo/v4"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

type adminAuditMetadata struct {
	target     string
	source     string
	reason     string
	code       string
	ttlSeconds int64
}

const (
	adminAuditMetaKey     = "admin_audit_metadata"
	adminAuditRecordedKey = "admin_audit_recorded"
)

func (s *Server) adminRiskBlocksList(c echov4.Context) error {
	r, err := s.adminSvc.RiskBlocksList(c.Request().Context(), admin.RiskBlocksListRequest{})
	return s.writeAdminResponse(c, r, err, "risk.blocks.list")
}

func (s *Server) adminRiskBlocksAdd(c echov4.Context) error {
	var req admin.RiskBlockAddRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "risk.blocks.add")
	}
	meta := adminAuditMetadata{ttlSeconds: req.TTLSeconds}
	if ip, err := risk.CanonicalIP(req.IP); err == nil {
		meta.target = admin.FingerprintIP(ip)
	}
	c.Set(adminAuditMetaKey, meta)
	req.Actor = adminActor(c, s.cfg)
	r, err := s.adminSvc.RiskBlocksAdd(c.Request().Context(), req)
	if err == nil {
		meta.target = r.Entry.IP
		meta.source = r.Entry.Source
		meta.reason = r.Entry.Reason
		c.Set(adminAuditMetaKey, meta)
	}
	return s.writeAdminResponse(c, r, err, "risk.blocks.add")
}

func (s *Server) adminRiskBlocksUnblock(c echov4.Context) error {
	var req admin.RiskBlockUnblockRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "risk.blocks.unblock")
	}
	meta := adminAuditMetadata{}
	if ip, err := risk.CanonicalIP(req.IP); err == nil {
		meta.target = admin.FingerprintIP(ip)
	}
	c.Set(adminAuditMetaKey, meta)
	req.Actor = adminActor(c, s.cfg)
	r, err := s.adminSvc.RiskBlocksUnblock(c.Request().Context(), req)
	if err == nil {
		meta.target = r.Entry.IP
		meta.source = r.Entry.Source
		meta.reason = r.Entry.Reason
		c.Set(adminAuditMetaKey, meta)
	}
	return s.writeAdminResponse(c, r, err, "risk.blocks.unblock")
}
