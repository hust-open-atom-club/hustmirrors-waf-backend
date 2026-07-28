package echo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	echov4 "github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/auth"
)

// TestFormatRiskTrace covers the rendering rules directly.
func TestFormatRiskTrace(t *testing.T) {
	assert.Empty(t, formatRiskTrace(nil))
	assert.Empty(t, formatRiskTrace([]auth.RiskTraceStep{}))

	// Unmatched steps carry no information about the verdict.
	assert.Empty(t, formatRiskTrace([]auth.RiskTraceStep{
		{Chain: "INPUT", Rule: "a", Matched: false},
		{Chain: "INPUT", Rule: "b", Matched: false},
	}))

	assert.Equal(t, "INPUT:reject-bad", formatRiskTrace([]auth.RiskTraceStep{
		{Chain: "INPUT", Rule: "skip", Matched: false},
		{Chain: "INPUT", Rule: "reject-bad", Matched: true},
	}))

	// A JUMP records where it went, which is what makes a multi-chain
	// verdict readable.
	assert.Equal(t, "INPUT:to-risk>RISK,RISK:block", formatRiskTrace([]auth.RiskTraceStep{
		{Chain: "INPUT", Rule: "to-risk", Matched: true, JumpTo: "RISK"},
		{Chain: "RISK", Rule: "block", Matched: true},
	}))
}

// TestFormatRiskTrace_Truncates: a long chain must not inflate every deny.
func TestFormatRiskTrace_Truncates(t *testing.T) {
	var steps []auth.RiskTraceStep
	for i := 0; i < 200; i++ {
		steps = append(steps, auth.RiskTraceStep{
			Chain: "INPUT", Rule: strings.Repeat("r", 20), Matched: true,
		})
	}
	got := formatRiskTrace(steps)
	assert.LessOrEqual(t, len(got), maxTraceHeaderLen+4)
	assert.True(t, strings.HasSuffix(got, ",..."), "a clipped trace must say so: %q", got)

	// A single step longer than the budget is also clipped rather than
	// emitted whole.
	long := formatRiskTrace([]auth.RiskTraceStep{
		{Chain: "INPUT", Rule: strings.Repeat("x", maxTraceHeaderLen*2), Matched: true},
	})
	assert.LessOrEqual(t, len(long), maxTraceHeaderLen+4)
	assert.True(t, strings.HasSuffix(long, ",..."))
}

// TestWriteAuthResult_TraceOnlyOnDeny pins where the header appears. The
// trace was computed on every risk-engine request and then discarded.
func TestWriteAuthResult_TraceOnlyOnDeny(t *testing.T) {
	trace := []auth.RiskTraceStep{
		{Chain: "INPUT", Rule: "reject-bad-ua", Matched: true},
	}

	deny := recordResult(t, auth.AuthResult{
		Allowed: false, HTTPStatus: 403, Reason: "blocked",
		ErrorHeader: "blocked", RiskTrace: trace,
	})
	assert.Equal(t, "INPUT:reject-bad-ua", deny.Header().Get("X-Pow-Trace"))

	allow := recordResult(t, auth.AuthResult{
		Allowed: true, HTTPStatus: 200, Reason: "ok", RiskTrace: trace,
	})
	assert.Empty(t, allow.Header().Get("X-Pow-Trace"),
		"an allow does not need explaining, so it stays off the hot path")

	// No risk engine means no trace, and no empty header either.
	bare := recordResult(t, auth.AuthResult{
		Allowed: false, HTTPStatus: 403, Reason: "missing_token_or_sign",
		ErrorHeader: "missing_token_or_sign",
	})
	_, present := bare.Header()["X-Pow-Trace"]
	assert.False(t, present, "no trace must mean no header, not an empty one")
}

func recordResult(t *testing.T, res auth.AuthResult) *httptest.ResponseRecorder {
	t.Helper()
	e := echov4.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/verify_pow", nil), rec)
	writeAuthResult(c, res)
	return rec
}
