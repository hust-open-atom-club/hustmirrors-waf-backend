package echo

import (
	"net/http"

	echov4 "github.com/labstack/echo/v4"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
)

func (s *Server) adminSystemPing(c echov4.Context) error {
	r, err := s.adminSvc.Ping(c.Request().Context(), admin.PingRequest{})
	return writeAdminResponse(c, r, err, "system.ping")
}

func (s *Server) adminSystemInfo(c echov4.Context) error {
	r, err := s.adminSvc.SystemInfo(c.Request().Context(), admin.SystemInfoRequest{})
	return writeAdminResponse(c, r, err, "system.info")
}

func (s *Server) adminConfigValidate(c echov4.Context) error {
	var req admin.ConfigValidateRequest
	if err := c.Bind(&req); err != nil {
		return writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body")
	}
	r, err := s.adminSvc.ConfigValidate(c.Request().Context(), req)
	return writeAdminResponse(c, r, err, "config.validate")
}

func (s *Server) adminRulePreview(c echov4.Context) error {
	var req admin.RulePreviewRequest
	if err := c.Bind(&req); err != nil {
		return writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body")
	}
	r, err := s.adminSvc.RulePreview(c.Request().Context(), req)
	return writeAdminResponse(c, r, err, "rule.preview")
}

func (s *Server) adminRuleReload(c echov4.Context) error {
	var req admin.RuleReloadRequest
	if err := c.Bind(&req); err != nil {
		return writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body")
	}
	r, err := s.adminSvc.RuleReload(c.Request().Context(), req)
	return writeAdminResponse(c, r, err, "rule.reload")
}

func writeAdminResponse(c echov4.Context, data interface{}, err error, action string) error {
	if err != nil {
		return writeAdminError(c, http.StatusInternalServerError, "INTERNAL", err.Error())
	}
	rid := c.Response().Header().Get(echov4.HeaderXRequestID)
	return c.JSON(http.StatusOK, admin.StandardResponse{
		OK:        true,
		Code:      "OK",
		Message:   "success",
		Data:      data,
		RequestID: rid,
	})
}

func writeAdminError(c echov4.Context, status int, code, message string) error {
	rid := c.Response().Header().Get(echov4.HeaderXRequestID)
	return c.JSON(status, admin.StandardResponse{
		OK:        false,
		Code:      code,
		Message:   message,
		RequestID: rid,
	})
}
