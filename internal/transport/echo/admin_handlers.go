package echo

import (
	"net/http"
	"strings"

	echov4 "github.com/labstack/echo/v4"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
)

func (s *Server) adminAuditMiddleware(next echov4.HandlerFunc) echov4.HandlerFunc {
	return func(c echov4.Context) error {
		err := next(c)
		if err != nil {
			c.Error(err)
		}
		if c.Get(adminAuditRecordedKey) != true {
			status := c.Response().Status
			outcome := "ok"
			detail := ""
			if status >= http.StatusBadRequest {
				outcome = "err"
				detail = http.StatusText(status)
				code := "HTTP_ERROR"
				switch status {
				case http.StatusUnauthorized:
					code = "UNAUTHORIZED"
				case http.StatusForbidden:
					code = "FORBIDDEN"
				case http.StatusRequestEntityTooLarge:
					code = "BODY_TOO_LARGE"
				}
				setAdminAuditCode(c, code)
			}
			action := strings.TrimPrefix(c.Path(), "/admin/api/")
			if action == "" {
				action = strings.TrimPrefix(c.Request().URL.Path, "/admin/api/")
			}
			s.recordAdminAction(c, action, outcome, detail)
		}
		return nil
	}
}

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
	if c.Get(adminAuditRecordedKey) == true {
		return
	}
	c.Set(adminAuditRecordedKey, true)
	if s.metrics != nil {
		s.metrics.AdminActions.WithLabelValues(action, outcome).Inc()
	}
	if s.auditLog != nil {
		meta, _ := c.Get(adminAuditMetaKey).(adminAuditMetadata)
		s.auditLog.Log(c.Request().Context(), admin.AuditEvent{
			Action:          action,
			Actor:           adminActor(c, s.cfg),
			RequestID:       c.Response().Header().Get(echov4.HeaderXRequestID),
			IP:              clientIP(c),
			Target:          meta.target,
			Source:          meta.source,
			Reason:          meta.reason,
			Code:            meta.code,
			TTLSeconds:      meta.ttlSeconds,
			Revision:        meta.revision,
			ChangeCount:     meta.changeCount,
			Danger:          meta.danger,
			RestartRequired: meta.restartRequired,
			OK:              outcome == "ok",
			Detail:          detail,
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
		if u, p, ok := c.Request().BasicAuth(); ok && u != "" &&
			cfg.Admin.Auth.Username != "" && cfg.Admin.Auth.Password != "" &&
			secureEqual(u, cfg.Admin.Auth.Username) && secureEqual(p, cfg.Admin.Auth.Password) {
			return u
		}
		return "unknown"
	case "token":
		got := bearerToken(c.Request().Header.Get("Authorization"))
		if got != "" && cfg.Admin.Auth.Token != "" && secureEqual(got, cfg.Admin.Auth.Token) {
			return "token"
		}
		return "unknown"
	}
	return "anonymous"
}

func (s *Server) writeAdminResponse(c echov4.Context, data interface{}, err error, action string) error {
	if err != nil {
		status := http.StatusInternalServerError
		code := "INTERNAL"
		message := "internal error"
		if rpcErr, ok := admin.AsRPCError(err); ok {
			status = rpcErr.Status
			code = rpcErr.Code
			message = rpcErr.Message
		}
		setAdminAuditCode(c, code)
		s.recordAdminAction(c, action, "err", message)
		return writeAdminErrorBody(c, status, code, message)
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
	setAdminAuditCode(c, code)
	s.recordAdminAction(c, action, "err", message)
	return writeAdminErrorBody(c, status, code, message)
}

func setAdminAuditCode(c echov4.Context, code string) {
	meta, _ := c.Get(adminAuditMetaKey).(adminAuditMetadata)
	meta.code = code
	c.Set(adminAuditMetaKey, meta)
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
