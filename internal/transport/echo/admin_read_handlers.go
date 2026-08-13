package echo

import (
	"net/http"
	"strings"

	echov4 "github.com/labstack/echo/v4"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
)

func (s *Server) adminSystemHealth(c echov4.Context) error {
	r, err := s.adminSvc.SystemHealth(c.Request().Context(), admin.SystemHealthRequest{})
	return s.writeAdminResponse(c, r, err, "system.health")
}

func (s *Server) adminDashboardSummary(c echov4.Context) error {
	r, err := s.adminSvc.DashboardSummary(c.Request().Context(), admin.DashboardSummaryRequest{})
	return s.writeAdminResponse(c, r, err, "dashboard.summary")
}

func (s *Server) adminDashboardSeries(c echov4.Context) error {
	var req admin.DashboardSeriesRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "dashboard.series")
	}
	r, err := s.adminSvc.DashboardSeries(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "dashboard.series")
}

func (s *Server) adminConfigGet(c echov4.Context) error {
	r, err := s.adminSvc.ConfigGet(c.Request().Context(), admin.ConfigGetRequest{})
	return s.writeAdminResponse(c, r, err, "config.get")
}

func (s *Server) adminRuleList(c echov4.Context) error {
	r, err := s.adminSvc.RuleList(c.Request().Context(), admin.RuleListRequest{})
	return s.writeAdminResponse(c, r, err, "rule.list")
}

func (s *Server) adminTokenGet(c echov4.Context) error {
	var req admin.TokenGetRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "token.get")
	}
	if strings.TrimSpace(req.SignID) == "" || len(req.SignID) > 128 {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid sign_id", "token.get")
	}
	r, err := s.adminSvc.TokenGet(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "token.get")
}

func (s *Server) adminPendingList(c echov4.Context) error {
	r, err := s.adminSvc.PendingList(c.Request().Context(), admin.PendingListRequest{})
	return s.writeAdminResponse(c, r, err, "pending.list")
}

func (s *Server) adminAuditList(c echov4.Context) error {
	var req admin.AuditListRequest
	if err := c.Bind(&req); err != nil {
		return s.writeAdminError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid request body", "audit.list")
	}
	r, err := s.adminSvc.AuditList(c.Request().Context(), req)
	return s.writeAdminResponse(c, r, err, "audit.list")
}
