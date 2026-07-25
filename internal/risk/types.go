package risk

// RequestContext carries everything a rule can see about a request.
type RequestContext struct {
	Path           string
	Method         string
	Args           string
	IP             string
	UserAgent      string
	HasToken       bool
	HasSign        bool
	// PowStatus is one of: missing, valid, invalid, expired, used_up.
	PowStatus string
	// PowMode is empty when no token was provided, otherwise "ip_bound"
	// or "generic".
	PowMode     string
	FileExt     string
	IsProtected bool
	IsRangeRequest bool
	// RiskScore is the optional ML-derived risk score; 0 means unset.
	RiskScore int
	// Counters is populated by the engine during evaluation when a rule's
	// Match.Counter condition is encountered.
	Counters CounterResolver
}

// CounterResolver returns the current value of a named counter for a
// given RequestContext. The engine passes a snapshot resolver that caches
// values fetched from the CounterStore during a single Evaluate pass, so
// multiple rules referencing the same counter do not multiply storage
// calls.
type CounterResolver interface {
	Get(name string) int64
}

type noopCounterResolver struct{}

func (noopCounterResolver) Get(_ string) int64 { return 0 }

var NoopCounterResolver CounterResolver = noopCounterResolver{}

type Decision struct {
	Target    string
	StatusCode int
	// LimitRate is the Nginx-style rate limit string (e.g. "512k").
	// Empty means "no limit".
	LimitRate string
	// Reason is forwarded to the client via X-Pow-Reason or X-Pow-Error.
	Reason string
	Chain string
	RuleName string
	Marks []string
}

type TraceStep struct {
	Chain   string `json:"chain"`
	Rule    string `json:"rule"`
	Matched bool   `json:"matched"`
	Target  string `json:"target,omitempty"`
	JumpTo  string `json:"jump_to,omitempty"`
}

type Result struct {
	Decision Decision
	Trace    []TraceStep
}
