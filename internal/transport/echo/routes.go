package echo

import (
	"net/http"

	echov4 "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (s *Server) registerMainRoutes() {
	s.echo.GET("/healthz", s.healthz)
	s.echo.GET("/readyz", s.readyz)
	s.echo.GET("/whoami", s.whoami)

	if s.metrics != nil {
		s.echo.GET("/metrics", echov4.WrapHandler(promhttp.Handler()))
	}

	s.echo.GET("/verify_pow", s.verifyPow, middleware.Gzip())
	// Some Nginx configs send POST for auth_request by mistake; accept it
	// and treat as GET.
	s.echo.POST("/verify_pow", s.verifyPow)
}

func (s *Server) registerAdminRoutes() {
	api := s.echo.Group("/admin/api",
		s.adminAuditMiddleware,
		adminAuthMiddleware(s.cfg.Admin),
		adminCIDRMiddleware(s.cfg.Admin),
	)
	api.POST("/system.ping", s.adminSystemPing)
	api.POST("/system.info", s.adminSystemInfo)
	api.POST("/config.validate", s.adminConfigValidate)
	api.POST("/config.status", s.adminConfigStatus)
	api.POST("/config.draft.save", s.adminConfigDraftSave)
	api.POST("/config.draft.get", s.adminConfigDraftGet)
	api.POST("/config.draft.discard", s.adminConfigDraftDiscard)
	api.POST("/config.diff", s.adminConfigDiff)
	api.POST("/config.apply", s.adminConfigApply)
	api.POST("/config.history", s.adminConfigHistory)
	api.POST("/config.history.get", s.adminConfigHistoryGet)
	api.POST("/config.rollback", s.adminConfigRollback)
	api.POST("/rule.preview", s.adminRulePreview)
	api.POST("/system.health", s.adminSystemHealth)
	api.POST("/dashboard.summary", s.adminDashboardSummary)
	api.POST("/dashboard.series", s.adminDashboardSeries)
	api.POST("/stats.summary", s.adminStatsSummary)
	api.POST("/stats.timeseries", s.adminStatsTimeseries)
	api.POST("/config.get", s.adminConfigGet)
	api.POST("/rule.list", s.adminRuleList)
	api.POST("/token.get", s.adminTokenGet)
	api.POST("/pending.list", s.adminPendingList)
	api.POST("/risk.blocks.list", s.adminRiskBlocksList)
	api.POST("/risk.blocks.add", s.adminRiskBlocksAdd)
	api.POST("/risk.blocks.unblock", s.adminRiskBlocksUnblock)
	api.POST("/audit.list", s.adminAuditList)
	api.POST("/audit.search", s.adminAuditSearch)

	// The SPA shell is protected by the network allow-list only. API calls
	// still carry their own admin credentials in the browser's memory.
	uiCIDR := adminCIDRMiddleware(s.cfg.Admin)
	s.echo.GET("/admin", s.adminUIRedirect, uiCIDR)
	s.echo.GET("/admin/*", s.adminUI, uiCIDR)
	s.echo.GET("/favicon.ico", func(c echov4.Context) error {
		return c.NoContent(http.StatusNoContent)
	})
}
