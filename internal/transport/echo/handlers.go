package echo

import (
	"net/http"
	"strconv"
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
		// Nginx's `limit_rate $var` requires a plain byte count; a value like
		// "512k" is treated as invalid and silently means "no limit". Emit the
		// numeric form in a separate header for the proxy to consume; the
		// human-readable form stays for logs and debugging.
		h.Set("X-Pow-Limit-Rate-Bytes", limitRateBytes(res.LimitRate))
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
	// Deny only: an allow needs no explaining, so the hot path stays clean.
	if t := formatRiskTrace(res.RiskTrace); t != "" {
		h.Set("X-Pow-Trace", t)
	}
	c.NoContent(res.HTTPStatus)
}

// maxTraceHeaderLen keeps a long chain from inflating every deny response.
const maxTraceHeaderLen = 512

// formatRiskTrace renders matched steps as "chain:rule", ">" marking a JUMP.
// Unmatched steps are dropped; rule.preview has the full trace.
func formatRiskTrace(steps []auth.RiskTraceStep) string {
	if len(steps) == 0 {
		return ""
	}
	var b strings.Builder
	for _, s := range steps {
		if !s.Matched {
			continue
		}
		entry := s.Chain + ":" + s.Rule
		if s.JumpTo != "" {
			entry += ">" + s.JumpTo
		}
		if b.Len() > 0 {
			if b.Len()+1+len(entry) > maxTraceHeaderLen {
				b.WriteString(",...")
				break
			}
			b.WriteByte(',')
		} else if len(entry) > maxTraceHeaderLen {
			return entry[:maxTraceHeaderLen] + ",..."
		}
		b.WriteString(entry)
	}
	return b.String()
}

func (s *Server) healthz(c echov4.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(c echov4.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok", "storage": "ok"})
}

// limitRateBytes converts a human rate string like "512k", "2m", "1g" or "0"
// into a plain byte count string. Unparseable input maps to "0" (no limit),
// matching how the risk engine treats unset rates.
func limitRateBytes(rate string) string {
	if rate == "" {
		return "0"
	}
	rate = strings.ToLower(strings.TrimSpace(rate))
	multiplier := int64(1)
	numeric := rate
	switch rate[len(rate)-1] {
	case 'k':
		multiplier = 1024
		numeric = rate[:len(rate)-1]
	case 'm':
		multiplier = 1024 * 1024
		numeric = rate[:len(rate)-1]
	case 'g':
		multiplier = 1024 * 1024 * 1024
		numeric = rate[:len(rate)-1]
	}
	value, err := strconv.ParseInt(numeric, 10, 64)
	if err != nil || value < 0 {
		return "0"
	}
	return strconv.FormatInt(value*multiplier, 10)
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
