package echo

import (
	"net/http"

	echov4 "github.com/labstack/echo/v4"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
)

func (s *Server) adminSystemPing(c echov4.Context) error {
	r, err := s.adminSvc.Ping(c.Request().Context(), admin.PingRequest{})
	return s.writeAdminResponse(c, r, err, "system.ping")
}

func (s *Server) adminSystemInfo(c echov4.Context) error {
	r, err := s.adminSvc.SystemInfo(c.Request().Context(), admin.SystemInfoRequest{})
	return s.writeAdminResponse(c, r, err, "system.info")
}

func (s *Server) adminConfigValidate(c echov4.Context) error {
	var req admin.ConfigValidateRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "config.validate")
	}
	r, err := s.adminSvc.ConfigValidate(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "config.validate")
}

func (s *Server) adminRulePreview(c echov4.Context) error {
	var req admin.RulePreviewRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "rule.preview")
	}
	r, err := s.adminSvc.RulePreview(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "rule.preview")
}

func (s *Server) adminRuleReload(c echov4.Context) error {
	var req admin.RuleReloadRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "rule.reload")
	}
	r, err := s.adminSvc.RuleReload(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "rule.reload")
}

// recordAdminAction bumps the admin_actions_total counter and writes the
// audit event. Every admin handler funnels through writeAdminResponse or
// writeAdminError, so recording here covers all of them - including the
// request-binding failures that never reach the service layer.
func (s *Server) recordAdminAction(c echov4.Context, action, outcome, detail string) {
	if s.metrics != nil {
		s.metrics.AdminActions.WithLabelValues(action, outcome).Inc()
	}
	if s.auditLog != nil {
		s.auditLog.Log(c.Request().Context(), admin.AuditEvent{
			Action:    action,
			Actor:     adminActor(c, s.cfg),
			RequestID: c.Response().Header().Get(echov4.HeaderXRequestID),
			IP:        clientIP(c),
			OK:        outcome == "ok",
			Detail:    detail,
		})
	}
}

// adminActor names the caller for the audit trail. Token auth has no
// identity beyond "the token holder", so it is reported as such rather
// than echoing any part of the credential.
func adminActor(c echov4.Context, cfg *config.Config) string {
	if cfg == nil {
		return "unknown"
	}
	switch cfg.Admin.Auth.Type {
	case "basic":
		if u, _, ok := c.Request().BasicAuth(); ok && u != "" {
			return u
		}
		return "unknown"
	case "token":
		return "token"
	}
	return "anonymous"
}

func (s *Server) writeAdminResponse(c echov4.Context, data interface{}, err error, action string) error {
	if err != nil {
		s.recordAdminAction(c, action, "err", err.Error())
		return writeAdminErrorBody(c, http.StatusInternalServerError, "INTERNAL", err.Error())
	}
	s.recordAdminAction(c, action, "ok", "")
	rid := c.Response().Header().Get(echov4.HeaderXRequestID)
	return c.JSON(http.StatusOK, admin.StandardResponse{
		OK:        true,
		Code:      "OK",
		Message:   "success",
		Data:      data,
		RequestID: rid,
	})
}

func (s *Server) writeAdminError(c echov4.Context, status int, code, message, action string) error {
	s.recordAdminAction(c, action, "err", message)
	return writeAdminErrorBody(c, status, code, message)
}

func writeAdminErrorBody(c echov4.Context, status int, code, message string) error {
	rid := c.Response().Header().Get(echov4.HeaderXRequestID)
	return c.JSON(status, admin.StandardResponse{
		OK:        false,
		Code:      code,
		Message:   message,
		RequestID: rid,
	})
}
