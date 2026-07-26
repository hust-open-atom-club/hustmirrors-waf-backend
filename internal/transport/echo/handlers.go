package echo

import (
	"net/http"
	"strings"

	echov4 "github.com/labstack/echo/v4"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/auth"
)

func (s *Server) verifyPow(c echov4.Context) error {
	req := auth.AuthRequest{
		OriginalURI:    c.Request().Header.Get("X-Original-URI"),
		OriginalMethod: c.Request().Header.Get("X-Original-Method"),
		OriginalArgs:   c.Request().Header.Get("X-Original-Args"),
		RealIP:         c.Request().Header.Get("X-Real-IP"),
		ForwardedFor:   c.Request().Header.Get("X-Forwarded-For"),
		UserAgent:      c.Request().Header.Get("User-Agent"),
		OriginalRange:  c.Request().Header.Get("X-Original-Range"),
	}
	res := s.authSvc.Verify(c.Request().Context(), req)
	writeAuthResult(c, res)
	return nil
}

func writeAuthResult(c echov4.Context, res auth.AuthResult) {
	h := c.Response().Header()
	if res.Mode != "" {
		h.Set("X-Pow-Mode", res.Mode)
	}
	if res.SignID != "" {
		if len(res.SignID) > 12 {
			h.Set("X-Pow-Sign-Id", res.SignID[:12])
		} else {
			h.Set("X-Pow-Sign-Id", res.SignID)
		}
	}
	if res.Uses > 0 || res.MaxUses > 0 {
		h.Set("X-Pow-Uses", itoa(res.Uses))
		h.Set("X-Pow-Max-Uses", itoa(res.MaxUses))
	}
	if res.LimitRate != "" {
		h.Set("X-Pow-Limit-Rate", res.LimitRate)
	}
	if res.Decision != "" {
		h.Set("X-Pow-Decision", res.Decision)
	}
	if res.RiskChain != "" {
		h.Set("X-Pow-Chain", res.RiskChain)
	}
	if res.RiskRule != "" {
		h.Set("X-Pow-Rule", res.RiskRule)
	}
	if len(res.RiskMarks) > 0 {
		h.Set("X-Pow-Marks", strings.Join(res.RiskMarks, ","))
	}

	if res.Allowed {
		h.Set("X-Pow-Result", "allow")
		h.Set("X-Pow-Reason", res.Reason)
		if res.DryRunOriginalError != "" {
			h.Set("X-Pow-Dry-Run-Original-Error", res.DryRunOriginalError)
		}
		c.NoContent(http.StatusOK)
		return
	}

	h.Set("X-Pow-Result", "deny")
	h.Set("X-Pow-Error", res.ErrorHeader)
	h.Set("X-Pow-Reason", res.Reason)
	c.NoContent(res.HTTPStatus)
}

func (s *Server) healthz(c echov4.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// whoami returns the caller's IP as this service sees it.
//
// The ip_bound PoW mode requires the client to embed its own public IP in
// the token, and that IP must match what the backend observes. Asking a
// third-party service (api.ipify.org) is unreliable and can disagree with
// us when the client is dual-stack or behind a different egress path, so
// the frontend asks the origin it is actually going to be verified by.
//
// Cache-Control is set explicitly: a cached response here would hand the
// browser a stale IP and produce ip_mismatch denials that are hard to
// diagnose.
func (s *Server) whoami(c echov4.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, map[string]string{"ip": clientIP(c)})
}

func (s *Server) readyz(c echov4.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok", "storage": "ok"})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
