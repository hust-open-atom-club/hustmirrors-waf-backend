package echo

import (
	"net/http"

	echov4 "github.com/labstack/echo/v4"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
)

func (s *Server) adminConfigStatus(c echov4.Context) error {
	r, err := s.adminSvc.ConfigStatus(c.Request().Context(), admin.ConfigStatusRequest{})
	return s.writeAdminResponse(c, r, err, "config.status")
}

func (s *Server) adminConfigDraftSave(c echov4.Context) error {
	var req admin.ConfigDraftSaveRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.draft.save")
	}
	r, err := s.adminSvc.ConfigDraftSave(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "config.draft.save")
}

func (s *Server) adminConfigDraftGet(c echov4.Context) error {
	var req admin.ConfigDraftGetRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.draft.get")
	}
	r, err := s.adminSvc.ConfigDraftGet(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "config.draft.get")
}

func (s *Server) adminConfigDraftDiscard(c echov4.Context) error {
	var req admin.ConfigDraftDiscardRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.draft.discard")
	}
	r, err := s.adminSvc.ConfigDraftDiscard(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "config.draft.discard")
}

func (s *Server) adminConfigDiff(c echov4.Context) error {
	var req admin.ConfigDiffRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.diff")
	}
	r, err := s.adminSvc.ConfigDiff(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "config.diff")
}

func (s *Server) adminConfigApply(c echov4.Context) error {
	var req admin.ConfigApplyRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.apply")
	}
	meta := adminAuditMetadata{}
	c.Set(adminAuditMetaKey, meta)
	req.Actor = adminActor(c, s.cfg)
	r, err := s.adminSvc.ConfigApply(c.Request().Context(), req)
	if err == nil {
		meta.reason = safeConfigAuditReason(req.Reason)
		meta.revision = r.Revision
		meta.changeCount = r.ChangeCount
		meta.danger = r.Danger
		meta.restartRequired = r.RestartRequired
		c.Set(adminAuditMetaKey, meta)
	}
	return s.writeAdminResponse(c, r, err, "config.apply")
}

func (s *Server) adminConfigHistory(c echov4.Context) error {
	var req admin.ConfigHistoryRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.history")
	}
	r, err := s.adminSvc.ConfigHistory(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "config.history")
}

func (s *Server) adminConfigHistoryGet(c echov4.Context) error {
	var req admin.ConfigHistoryGetRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.history.get")
	}
	r, err := s.adminSvc.ConfigHistoryGet(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "config.history.get")
}

func (s *Server) adminConfigRollback(c echov4.Context) error {
	var req admin.ConfigRollbackRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.rollback")
	}
	meta := adminAuditMetadata{}
	c.Set(adminAuditMetaKey, meta)
	req.Actor = adminActor(c, s.cfg)
	r, err := s.adminSvc.ConfigRollback(c.Request().Context(), req)
	if err == nil {
		meta.reason = safeConfigAuditReason(req.Reason)
		meta.revision = r.Revision
		meta.changeCount = r.ChangeCount
		meta.danger = r.Danger
		meta.restartRequired = r.RestartRequired
		c.Set(adminAuditMetaKey, meta)
	}
	return s.writeAdminResponse(c, r, err, "config.rollback")
}

func safeConfigAuditReason(value string) string {
	if len(value) > 256 {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}
