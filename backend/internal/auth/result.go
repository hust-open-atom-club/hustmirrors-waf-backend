package auth

// AuthResult is the outcome of a verification. The transport layer maps
// it onto HTTP status codes and X-Pow-* headers.
type AuthResult struct {
	Allowed     bool
	HTTPStatus  int
	Reason      string
	Mode        string
	SignID      string
	Uses        int
	MaxUses     int
	ErrorHeader string
	LimitRate   string
	Decision    string
	// DryRunOriginalError carries the would-have-been error when dry-run
	// mode rewrites a deny into an allow.
	DryRunOriginalError string
	RiskChain           string
	RiskRule            string
	RiskTrace           []RiskTraceStep
	// RiskMarks carries the marks accumulated by MARK targets during
	// risk-engine evaluation. Empty when no MARK rule fired.
	RiskMarks []string
}

// RiskTraceStep mirrors risk.TraceStep but breaks the dependency so the
// transport layer can serialise it without importing internal/risk.
type RiskTraceStep struct {
	Chain   string `json:"chain"`
	Rule    string `json:"rule"`
	Matched bool   `json:"matched"`
	Target  string `json:"target,omitempty"`
	JumpTo  string `json:"jump_to,omitempty"`
}

// allow returns a 200 result with Decision=verified. Used for PoW-valid
// and not-protected paths.
func allow(reason, mode string) AuthResult {
	return AuthResult{
		Allowed:    true,
		HTTPStatus: 200,
		Reason:     reason,
		Mode:       mode,
		Decision:   DecisionVerified,
	}
}

// allowDecision returns a 200 result with an explicit decision. Used
// when the decision category isn't "verified" (e.g. not_protected,
// bypass, dry_run).
func allowDecision(reason, mode, decision string) AuthResult {
	return AuthResult{
		Allowed:    true,
		HTTPStatus: 200,
		Reason:     reason,
		Mode:       mode,
		Decision:   decision,
	}
}

// deny returns a 403 result with Decision=denied and ErrorHeader set to
// reason. mode is empty for pre-token failures.
func deny(reason string) AuthResult {
	return AuthResult{
		Allowed:     false,
		HTTPStatus:  statusForReason(reason),
		Reason:      reason,
		ErrorHeader: reason,
		Decision:    DecisionDenied,
	}
}

// denyMode is deny with the PoW mode attached.
func denyMode(reason, mode string) AuthResult {
	r := deny(reason)
	r.Mode = mode
	return r
}

// denyStatus is deny with an explicit HTTP status. Used when the status
// isn't the canonical one for the reason (e.g. storage_error -> 500).
func denyStatus(status int, reason, mode string) AuthResult {
	r := denyMode(reason, mode)
	r.HTTPStatus = status
	return r
}
