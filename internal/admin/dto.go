package admin

import "time"

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
	ConfigYAML    string `json:"config_yaml,omitempty"`
	DraftID       string `json:"draft_id,omitempty"`
	DraftRevision uint64 `json:"draft_revision,omitempty"`
}

type ConfigValidateResponse struct {
	OK              bool     `json:"ok"`
	Valid           bool     `json:"valid"`
	Problems        []string `json:"problems,omitempty"`
	Error           string   `json:"error,omitempty"`
	DraftID         string   `json:"draft_id,omitempty"`
	DraftRevision   uint64   `json:"draft_revision,omitempty"`
	RestartRequired bool     `json:"restart_required"`
}

type ConfigStatusRequest struct{}

type ConfigStatusResponse struct {
	Managed         bool               `json:"managed"`
	CurrentRevision uint64             `json:"current_revision,omitempty"`
	PendingRestart  bool               `json:"pending_restart"`
	Draft           *DraftSummary      `json:"draft,omitempty"`
	Capabilities    ConfigCapabilities `json:"capabilities"`
}

type ConfigCapabilities struct {
	Managed          bool `json:"managed"`
	MutationsEnabled bool `json:"mutations_enabled"`
	ApplyEnabled     bool `json:"apply_enabled"`
	HistoryEnabled   bool `json:"history_enabled"`
}

type DraftSummary struct {
	ID           string `json:"id"`
	Revision     uint64 `json:"revision"`
	BaseRevision uint64 `json:"base_revision"`
	UpdatedAt    int64  `json:"updated_at"`
	Validated    bool   `json:"validated"`
}

type ConfigDraftSaveRequest struct {
	DraftID               string `json:"draft_id,omitempty"`
	ExpectedDraftRevision uint64 `json:"expected_draft_revision,omitempty"`
	BaseRevision          uint64 `json:"base_revision,omitempty"`
	ConfigYAML            string `json:"config_yaml"`
}

type ConfigDraftGetRequest struct {
	DraftID string `json:"draft_id,omitempty"`
}
type ConfigDraftDiscardRequest struct {
	DraftID               string `json:"draft_id"`
	ExpectedDraftRevision uint64 `json:"expected_draft_revision"`
}

type ConfigDraftResponse struct {
	DraftID       string `json:"draft_id"`
	DraftRevision uint64 `json:"draft_revision"`
	BaseRevision  uint64 `json:"base_revision"`
	UpdatedAt     int64  `json:"updated_at"`
	ConfigYAML    string `json:"config_yaml"`
	Validated     bool   `json:"validated"`
}

type ConfigDiffRequest struct {
	DraftID        string `json:"draft_id,omitempty"`
	DraftRevision  uint64 `json:"draft_revision,omitempty"`
	TargetRevision uint64 `json:"target_revision,omitempty"`
}

type ConfigDiffChange struct {
	Path            string      `json:"path"`
	Kind            string      `json:"kind"`
	Before          interface{} `json:"before,omitempty"`
	After           interface{} `json:"after,omitempty"`
	Sensitive       bool        `json:"sensitive"`
	Danger          string      `json:"danger"`
	RestartRequired bool        `json:"restart_required"`
}

type ConfigDiffResponse struct {
	PreviewID          string             `json:"preview_id"`
	BaseRevision       uint64             `json:"base_revision"`
	CandidateRevision  uint64             `json:"candidate_revision,omitempty"`
	Changes            []ConfigDiffChange `json:"changes"`
	Danger             string             `json:"danger"`
	RestartRequired    bool               `json:"restart_required"`
	ConfirmationPhrase string             `json:"confirmation_phrase,omitempty"`
}

type ConfigApplyRequest struct {
	DraftID            string `json:"draft_id,omitempty"`
	DraftRevision      uint64 `json:"draft_revision,omitempty"`
	PreviewID          string `json:"preview_id"`
	ExpectedRevision   uint64 `json:"expected_revision"`
	Reason             string `json:"reason"`
	Acknowledged       bool   `json:"acknowledged"`
	ConfirmationPhrase string `json:"confirmation_phrase,omitempty"`
	Actor              string `json:"-"`
}

type ConfigApplyResponse struct {
	PreviousRevision uint64 `json:"previous_revision"`
	Revision         uint64 `json:"revision"`
	ChangeCount      int    `json:"change_count"`
	Danger           string `json:"danger"`
	RuntimeApplied   bool   `json:"runtime_applied"`
	RestartRequired  bool   `json:"restart_required"`
}

type ConfigHistoryRequest struct {
	Limit int `json:"limit"`
}
type ConfigHistoryResponse struct {
	Entries []ConfigHistoryEntry `json:"entries"`
}
type ConfigHistoryEntry struct {
	Revision        uint64 `json:"revision"`
	ParentRevision  uint64 `json:"parent_revision,omitempty"`
	Action          string `json:"action"`
	Actor           string `json:"actor,omitempty"`
	Reason          string `json:"reason,omitempty"`
	RollbackTarget  uint64 `json:"rollback_target,omitempty"`
	Changed         int    `json:"changed"`
	Danger          string `json:"danger,omitempty"`
	RestartRequired bool   `json:"restart_required"`
	CreatedAt       int64  `json:"created_at"`
}

type ConfigHistoryGetRequest struct {
	Revision uint64 `json:"revision"`
}
type ConfigHistoryGetResponse struct {
	Revision   ConfigHistoryEntry `json:"revision"`
	ConfigYAML string             `json:"config_yaml"`
}

type ConfigRollbackRequest struct {
	TargetRevision     uint64 `json:"target_revision"`
	PreviewID          string `json:"preview_id"`
	ExpectedRevision   uint64 `json:"expected_revision"`
	Reason             string `json:"reason"`
	Acknowledged       bool   `json:"acknowledged"`
	ConfirmationPhrase string `json:"confirmation_phrase,omitempty"`
	Actor              string `json:"-"`
}

type ConfigRollbackResponse = ConfigApplyResponse

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
	Config          map[string]interface{} `json:"config"`
	EditableYAML    string                 `json:"editable_yaml,omitempty"`
	Managed         bool                   `json:"managed"`
	CurrentRevision uint64                 `json:"current_revision,omitempty"`
	PendingRestart  bool                   `json:"pending_restart"`
	Capabilities    ConfigCapabilities     `json:"capabilities"`
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
	Timestamp       int64  `json:"timestamp"`
	Action          string `json:"action"`
	Actor           string `json:"actor"`
	RequestID       string `json:"request_id,omitempty"`
	IP              string `json:"ip,omitempty"`
	Target          string `json:"target,omitempty"`
	Source          string `json:"source,omitempty"`
	Reason          string `json:"reason,omitempty"`
	Code            string `json:"code,omitempty"`
	TTLSeconds      int64  `json:"ttl_seconds,omitempty"`
	Revision        uint64 `json:"revision,omitempty"`
	ChangeCount     int    `json:"change_count,omitempty"`
	Danger          string `json:"danger,omitempty"`
	RestartRequired bool   `json:"restart_required,omitempty"`
	OK              bool   `json:"ok"`
	Detail          string `json:"detail,omitempty"`
}

// Runtime override (emergency switch) DTOs.

type RuntimeStatusRequest struct{}

type RuntimeSwitchDTO struct {
	Key           string `json:"key"`
	ConfigValue   bool   `json:"config_value"`
	ActiveValue   bool   `json:"active_value"`
	Overridden    bool   `json:"overridden"`
	Reason        string `json:"reason,omitempty"`
	MaxTTLSeconds int    `json:"max_ttl_seconds"`
	Description   string `json:"description"`
}

type RuntimeOverrideDTO struct {
	Key       string    `json:"key"`
	Value     bool      `json:"value"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

type RuntimeStatusResponse struct {
	Switches  []RuntimeSwitchDTO  `json:"switches"`
	Overrides []RuntimeOverrideDTO `json:"overrides"`
}

type RuntimeOverrideSetRequest struct {
	Key        string `json:"key"`
	Value      bool   `json:"value"`
	Reason     string `json:"reason"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type RuntimeOverrideClearRequest struct {
	Key string `json:"key"`
}
