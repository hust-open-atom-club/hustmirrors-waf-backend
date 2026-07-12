package admin

type StandardResponse struct {
	OK        bool        `json:"ok"`
	Code      string      `json:"code"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
}

type PingRequest struct{}

type PingResponse struct {
	OK bool `json:"ok"`
}

type SystemInfoRequest struct{}

type SystemInfoResponse struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

type ConfigValidateRequest struct {
	ConfigYAML string `json:"config_yaml"`
}

type ConfigValidateResponse struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems,omitempty"`
	Error    string   `json:"error,omitempty"`
}

type RulePreviewRequest struct {
	Request RulePreviewRequestContext `json:"request"`
}

type RulePreviewRequestContext struct {
	Path           string `json:"path"`
	Method         string `json:"method"`
	IP             string `json:"ip"`
	UserAgent      string `json:"user_agent"`
	PowStatus      string `json:"pow_status"`
	PowMode        string `json:"pow_mode"`
	IsProtected    bool   `json:"is_protected"`
	IsRangeRequest bool   `json:"is_range_request"`
}

type RulePreviewResponse struct {
	OK       bool           `json:"ok"`
	Decision DecisionDTO    `json:"decision,omitempty"`
	Trace    []TraceStepDTO `json:"trace,omitempty"`
	Error    string         `json:"error,omitempty"`
}

type DecisionDTO struct {
	Target     string `json:"target"`
	StatusCode int    `json:"status_code"`
	LimitRate  string `json:"limit_rate"`
	Reason     string `json:"reason"`
	Chain      string `json:"chain"`
	RuleName   string `json:"rule_name"`
}

type TraceStepDTO struct {
	Chain   string `json:"chain"`
	Rule    string `json:"rule"`
	Matched bool   `json:"matched"`
	Target  string `json:"target,omitempty"`
	JumpTo  string `json:"jump_to,omitempty"`
}

type RuleReloadRequest struct{}

type RuleReloadResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}
