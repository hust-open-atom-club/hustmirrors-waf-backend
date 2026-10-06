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
