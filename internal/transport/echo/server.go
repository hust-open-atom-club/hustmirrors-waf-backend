package echo

import (
	"context"
	"net/http"
	"time"

	echov4 "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/auth"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
)

type Server struct {
	echo       *echov4.Echo
	cfg        *config.Config
	logger     logging.Logger
	metrics    *metrics.Container
	authSvc    *auth.Service
	adminSvc   *admin.Service
	auditLog   admin.AuditLogger
	httpServer *http.Server
}

type MainOptions struct {
	Config  *config.Config
	Logger  logging.Logger
	Metrics *metrics.Container
	AuthSvc *auth.Service
}

func NewMain(opts MainOptions) *Server {
	e := echov4.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = errorHandler(opts.Logger)

	e.Use(middleware.Recover())
	if opts.Logger != nil {
		e.Use(requestIDMiddleware(opts.Logger))
	}
	e.Use(middleware.BodyLimit("1K"))
	e.Use(timeoutMiddleware(opts.Config.Server.ReadTimeout, opts.Config.Server.WriteTimeout))

	s := &Server{
		echo:    e,
		cfg:     opts.Config,
		logger:  opts.Logger,
		metrics: opts.Metrics,
		authSvc: opts.AuthSvc,
	}
	s.registerMainRoutes()
	return s
}

type AdminOptions struct {
	Config   *config.Config
	Logger   logging.Logger
	Metrics  *metrics.Container
	AdminSvc *admin.Service
}

func NewAdmin(opts AdminOptions) *Server {
	e := echov4.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = errorHandler(opts.Logger)

	e.Use(middleware.Recover())
	if opts.Logger != nil {
		e.Use(requestIDMiddleware(opts.Logger))
	}
	e.Use(middleware.BodyLimit("256K"))

	s := &Server{
		echo:     e,
		cfg:      opts.Config,
		logger:   opts.Logger,
		metrics:  opts.Metrics,
		adminSvc: opts.AdminSvc,
		auditLog: admin.NewLogAuditLogger(opts.Logger),
	}
	s.registerAdminRoutes()
	return s
}

func (s *Server) Start(listen string) error {
	s.httpServer = &http.Server{
		Addr:              listen,
		Handler:           s.echo,
		ReadHeaderTimeout: 5 * time.Second,
		// All input arrives in headers (X-Original-*, User-Agent), never
		// the body, so BodyLimit bounds nothing that matters. Go defaults
		// to 1MB of headers; 64KB is well above any real PoW token.
		MaxHeaderBytes: 64 << 10,
	}
	if s.cfg.Server.ReadTimeout > 0 {
		s.httpServer.ReadTimeout = s.cfg.Server.ReadTimeout
	}
	if s.cfg.Server.WriteTimeout > 0 {
		s.httpServer.WriteTimeout = s.cfg.Server.WriteTimeout
	}
	if s.cfg.Server.IdleTimeout > 0 {
		s.httpServer.IdleTimeout = s.cfg.Server.IdleTimeout
	}
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Echo() *echov4.Echo { return s.echo }

func errorHandler(logger logging.Logger) echov4.HTTPErrorHandler {
	return func(err error, c echov4.Context) {
		if c.Response().Committed {
			return
		}
		if he, ok := err.(*echov4.HTTPError); ok {
			_ = c.JSON(he.Code, map[string]string{"error": err.Error()})
			return
		}
		if logger != nil {
			logger.Error(c.Request().Context(), "unhandled error", logging.Err(err))
		}
		_ = c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal"})
	}
}
