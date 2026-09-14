package echo

import (
	"context"
	"crypto/subtle"
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

// adminAuthMiddleware builds the auth gate for the admin API.
//
// Unlike pow.CompareSign - which compares a hash both sides can derive -
// these credentials are real secrets, so all comparisons use
// subtle.ConstantTimeCompare. A short-circuiting != leaks how many leading
// bytes of a guess were correct, which turns an offline brute force into a
// far cheaper byte-at-a-time search.
func adminAuthMiddleware(cfg config.AdminConfig) echov4.MiddlewareFunc {
	expected := cfg.Auth.Token
	if expected == "" {
		// Unauthenticated admin API. Config validation rejects this unless
		// the listener is loopback or CIDR allow-listed, so this is not a
		// silent open door.
		return func(next echov4.HandlerFunc) echov4.HandlerFunc { return next }
	}
	return func(next echov4.HandlerFunc) echov4.HandlerFunc {
		return func(c echov4.Context) error {
			got := bearerToken(c.Request().Header.Get("Authorization"))
			if got == "" || !secureEqual(got, expected) {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid admin token"})
			}
			return next(c)
		}
	}
}

// secureEqual compares two secrets in constant time with respect to their
// contents. Length is not hidden, which is standard and acceptable here.
func secureEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
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
