package echo

import (
	"context"
	"net/http"
	"strings"
	"time"

	echov4 "github.com/labstack/echo/v4"
	middleware "github.com/labstack/echo/v4/middleware"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
)

func requestIDMiddleware(logger logging.Logger) echov4.MiddlewareFunc {
	mw := middleware.RequestIDWithConfig(middleware.RequestIDConfig{
		Generator: func() string { return generateRequestID() },
	})
	return func(next echov4.HandlerFunc) echov4.HandlerFunc {
		wrapped := mw(next)
		return func(c echov4.Context) error {
			err := wrapped(c)
			rid := c.Response().Header().Get(echov4.HeaderXRequestID)
			if rid == "" {
				rid = c.Request().Header.Get("X-Request-Id")
			}
			if rid != "" && logger != nil {
				ctx := logging.WithFields(c.Request().Context(),
					logging.FieldForRequestID(rid))
				c.SetRequest(c.Request().WithContext(ctx))
			}
			return err
		}
	}
}

func generateRequestID() string {
	return itoa64(time.Now().UnixNano())
}

func itoa64(n int64) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = alphabet[n%36]
		n /= 36
	}
	return string(buf[i:])
}

func timeoutMiddleware(read, write time.Duration) echov4.MiddlewareFunc {
	if read <= 0 && write <= 0 {
		return func(next echov4.HandlerFunc) echov4.HandlerFunc { return next }
	}
	d := write
	if d <= 0 {
		d = read
	}
	if d <= 0 {
		d = 2 * time.Second
	}
	return func(next echov4.HandlerFunc) echov4.HandlerFunc {
		return func(c echov4.Context) error {
			ctx, cancel := context.WithTimeout(c.Request().Context(), d)
			defer cancel()
			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}

func adminAuthMiddleware(cfg config.AdminConfig) echov4.MiddlewareFunc {
	switch cfg.Auth.Type {
	case "token":
		expected := cfg.Auth.Token
		return func(next echov4.HandlerFunc) echov4.HandlerFunc {
			return func(c echov4.Context) error {
				if expected == "" {
					return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "admin token not configured"})
				}
				got := bearerToken(c.Request().Header.Get("Authorization"))
				if got == "" || got != expected {
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid admin token"})
				}
				return next(c)
			}
		}
	case "basic":
		expectedUser, expectedPass := cfg.Auth.Username, cfg.Auth.Password
		return func(next echov4.HandlerFunc) echov4.HandlerFunc {
			return func(c echov4.Context) error {
				u, p, ok := c.Request().BasicAuth()
				if !ok || u != expectedUser || p != expectedPass {
					c.Response().Header().Set("WWW-Authenticate", `Basic realm="mirrors-waf-admin"`)
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
				}
				return next(c)
			}
		}
	case "none", "":
		return func(next echov4.HandlerFunc) echov4.HandlerFunc { return next }
	}
	return func(next echov4.HandlerFunc) echov4.HandlerFunc { return next }
}

func adminCIDRMiddleware(cfg config.AdminConfig) echov4.MiddlewareFunc {
	if len(cfg.AllowCIDRs) == 0 {
		return func(next echov4.HandlerFunc) echov4.HandlerFunc { return next }
	}
	return func(next echov4.HandlerFunc) echov4.HandlerFunc {
		return func(c echov4.Context) error {
			ip := clientIP(c)
			if !ipAllowed(ip, cfg.AllowCIDRs) {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "ip not allowed"})
			}
			return next(c)
		}
	}
}

func bearerToken(h string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
