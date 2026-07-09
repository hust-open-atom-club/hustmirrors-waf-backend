package echo

import (
	echov4 "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (s *Server) registerMainRoutes() {
	s.echo.GET("/healthz", s.healthz)
	s.echo.GET("/readyz", s.readyz)

	if s.metrics != nil {
		s.echo.GET("/metrics", echov4.WrapHandler(promhttp.Handler()))
	}

	s.echo.GET("/verify_pow", s.verifyPow, middleware.Gzip())
	// Some Nginx configs send POST for auth_request by mistake; accept it
	// and treat as GET.
	s.echo.POST("/verify_pow", s.verifyPow)
}

func (s *Server) registerAdminRoutes() {
	g := s.echo.Group("/admin/api",
		adminAuthMiddleware(s.cfg.Admin),
		adminCIDRMiddleware(s.cfg.Admin),
	)
	g.POST("/system.ping", s.adminSystemPing)
	g.POST("/system.info", s.adminSystemInfo)
	g.POST("/config.validate", s.adminConfigValidate)
	g.POST("/rule.preview", s.adminRulePreview)
	g.POST("/rule.reload", s.adminRuleReload)
}
