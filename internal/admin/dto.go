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

type DashboardSummaryRequest struct{}

type DashboardSummaryResponse struct {
	Available bool                   `json:"available"`
	Window    string                 `json:"window"`
	Metrics   DashboardMetricSummary `json:"metrics"`
	Sources   []SourceStatus         `json:"sources"`
}

type DashboardMetricSummary struct {
	PowVerifyTotal    float64 `json:"pow_verify_total"`
	PowAllowedTotal   float64 `json:"pow_allowed_total"`
	PowDeniedTotal    float64 `json:"pow_denied_total"`
	RiskDecisionTotal float64 `json:"risk_decision_total"`
	ActiveSignatures  float64 `json:"active_signatures"`
}

type DashboardSeriesRequest struct {
	Metric string `json:"metric"`
	From   int64  `json:"from"`
	To     int64  `json:"to"`
	Step   int64  `json:"step"`
}

type DashboardSeriesResponse struct {
	Available bool             `json:"available"`
	Metric    string           `json:"metric"`
	Points    []MetricPointDTO `json:"points"`
	Error     string           `json:"error,omitempty"`
}

type MetricPointDTO struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

type SourceStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Latency int64  `json:"latency_ms,omitempty"`
}

type SystemHealthRequest struct{}

type SystemHealthResponse struct {
	OK         bool           `json:"ok"`
	Components []SourceStatus `json:"components"`
}

type ConfigGetRequest struct{}

type ConfigGetResponse struct {
	Config map[string]interface{} `json:"config"`
}

type RuleListRequest struct{}

type RuleListResponse struct {
	RiskControlEnabled bool           `json:"risk_control_enabled"`
	Chains             []RuleChainDTO `json:"chains"`
}

type RuleChainDTO struct {
	Name   string        `json:"name"`
	Policy DecisionDTO   `json:"policy"`
	Rules  []RuleItemDTO `json:"rules"`
}

type RuleItemDTO struct {
	Name      string      `json:"name"`
	Match     interface{} `json:"match"`
	Target    string      `json:"target"`
	Chain     string      `json:"chain,omitempty"`
	Status    int         `json:"status,omitempty"`
	LimitRate string      `json:"limit_rate,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	Mark      string      `json:"mark,omitempty"`
}

type TokenGetRequest struct {
	SignID string `json:"sign_id"`
}

type TokenGetResponse struct {
	Found bool           `json:"found"`
	Token TokenRecordDTO `json:"token,omitempty"`
}

type TokenRecordDTO struct {
	ID        string `json:"id"`
	Mode      string `json:"mode"`
	Path      string `json:"path"`
	Uses      int    `json:"uses"`
	MaxUses   int    `json:"max_uses"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	IPHint    string `json:"ip_hint,omitempty"`
}

type PendingListRequest struct{}

type PendingListResponse struct {
	Scope            string            `json:"scope"`
	MutationsEnabled bool              `json:"mutations_enabled"`
	Entries          []PendingEntryDTO `json:"entries"`
}

type PendingEntryDTO struct {
	IP           string `json:"ip"`
	Pending      int    `json:"pending"`
	Blocked      bool   `json:"blocked"`
	BlockedUntil int64  `json:"blocked_until,omitempty"`
	Source       string `json:"source,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Actor        string `json:"actor,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`
	UpdatedAt    int64  `json:"updated_at,omitempty"`
}

type RiskBlocksListRequest struct{}

type RiskBlocksListResponse = PendingListResponse

type RiskBlockAddRequest struct {
	IP         string `json:"ip"`
	ConfirmIP  string `json:"confirm_ip"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Reason     string `json:"reason"`
	Actor      string `json:"-"`
}

type RiskBlockUnblockRequest struct {
	IP        string `json:"ip"`
	ConfirmIP string `json:"confirm_ip"`
	Actor     string `json:"-"`
}

type RiskBlockMutationResponse struct {
	Scope   string          `json:"scope"`
	Changed bool            `json:"changed"`
	Entry   PendingEntryDTO `json:"entry"`
}

type AuditListRequest struct {
	From  int64 `json:"from"`
	To    int64 `json:"to"`
	Limit int   `json:"limit"`
}

type AuditListResponse struct {
	Available bool            `json:"available"`
	Events    []AuditEventDTO `json:"events"`
	Error     string          `json:"error,omitempty"`
}

type AuditEventDTO struct {
	Timestamp  int64  `json:"timestamp"`
	Action     string `json:"action"`
	Actor      string `json:"actor"`
	RequestID  string `json:"request_id,omitempty"`
	IP         string `json:"ip,omitempty"`
	Target     string `json:"target,omitempty"`
	Source     string `json:"source,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Code       string `json:"code,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	OK         bool   `json:"ok"`
	Detail     string `json:"detail,omitempty"`
}
