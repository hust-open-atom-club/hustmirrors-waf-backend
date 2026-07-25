package echo

import (
	"net"
	"strings"

	echov4 "github.com/labstack/echo/v4"
)

func clientIP(c echov4.Context) string {
	if v := c.Request().Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := c.Request().Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	host, _, err := net.SplitHostPort(c.Request().RemoteAddr)
	if err != nil {
		return c.Request().RemoteAddr
	}
	return host
}

func ipAllowed(ip string, cidrs []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
