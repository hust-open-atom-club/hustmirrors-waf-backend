package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

func (s *Service) DashboardSummary(_ context.Context, _ DashboardSummaryRequest) (DashboardSummaryResponse, error) {
	result := DashboardSummaryResponse{
		Available: s.metrics != nil,
		Window:    "process",
		Sources:   []SourceStatus{},
	}
	if s.metrics == nil {
		result.Sources = append(result.Sources, SourceStatus{Name: "process_metrics", Status: "disabled"})
		return result, nil
	}
	snapshot := s.metrics.Snapshot()
	result.Metrics = DashboardMetricSummary{
		PowVerifyTotal:    snapshot.PowVerifyTotal,
		PowAllowedTotal:   snapshot.PowAllowedTotal,
		PowDeniedTotal:    snapshot.PowDeniedTotal,
		RiskDecisionTotal: snapshot.RiskDecisionTotal,
		ActiveSignatures:  snapshot.ActiveSignatures,
	}
	result.Sources = append(result.Sources, SourceStatus{Name: "process_metrics", Status: "ok"})
	return result, nil
}

func (s *Service) DashboardSeries(ctx context.Context, req DashboardSeriesRequest) (DashboardSeriesResponse, error) {
	result := DashboardSeriesResponse{Available: false, Metric: req.Metric, Points: []MetricPointDTO{}}
	if _, ok := metricQueries[req.Metric]; !ok {
		result.Error = fmt.Sprintf("unsupported metric %q", req.Metric)
		return result, nil
	}
	if s.prometheus == nil {
		result.Error = "prometheus is not configured"
		return result, nil
	}
	points, err := s.prometheus.queryRange(ctx, req)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	result.Available = true
	result.Points = points
	return result, nil
}

func (s *Service) SystemHealth(ctx context.Context, _ SystemHealthRequest) (SystemHealthResponse, error) {
	components := []SourceStatus{
		{Name: "admin_api", Status: "ok"},
	}
	if s.metrics == nil {
		components = append(components, SourceStatus{Name: "process_metrics", Status: "disabled"})
	} else {
		components = append(components, SourceStatus{Name: "process_metrics", Status: "ok"})
	}
	if !hasProbe(s.probes, "usage_store") {
		status := "disabled"
		if s.usage != nil {
			status = "configured"
		}
		components = append(components, SourceStatus{Name: "usage_store", Status: status})
	}
	if s.pending == nil {
		components = append(components, SourceStatus{Name: "pending_blocker", Status: "disabled"})
	} else {
		components = append(components, SourceStatus{Name: "pending_blocker", Status: "ok", Detail: "instance scoped"})
	}
	if s.prometheus == nil {
		components = append(components, SourceStatus{Name: "prometheus", Status: "disabled"})
	} else {
		components = append(components, runExternalProbe(ctx, "prometheus", s.prometheus.health, s.queryTimeout()))
	}
	if s.loki == nil {
		components = append(components, SourceStatus{Name: "loki", Status: "disabled"})
	} else {
		components = append(components, runExternalProbe(ctx, "loki", s.loki.health, s.queryTimeout()))
	}
	for _, probe := range s.probes {
		components = append(components, probe.run(ctx))
	}
	sort.SliceStable(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	ok := true
	for _, component := range components {
		if component.Status == "error" {
			ok = false
			break
		}
	}
	return SystemHealthResponse{OK: ok, Components: components}, nil
}

func (s *Service) ConfigGet(_ context.Context, _ ConfigGetRequest) (ConfigGetResponse, error) {
	if s.cfg == nil {
		return ConfigGetResponse{Config: map[string]interface{}{}}, nil
	}
	c := s.cfg
	configView := map[string]interface{}{
		"server": map[string]interface{}{
			"listen": c.Server.Listen, "read_timeout": c.Server.ReadTimeout.String(),
			"write_timeout": c.Server.WriteTimeout.String(), "idle_timeout": c.Server.IdleTimeout.String(),
			"shutdown_timeout": c.Server.ShutdownTimeout.String(),
		},
		"pow": map[string]interface{}{
			"enabled": boolValue(c.Pow.Enabled), "dry_run": c.Pow.DryRun, "bypass_all": c.Pow.BypassAll,
			"token_param": c.Pow.TokenParam, "sign_param": c.Pow.SignParam,
			"max_token_length": c.Pow.MaxTokenLength, "max_sign_length": c.Pow.MaxSignLength,
			"algorithm": c.Pow.Algorithm, "public_salt": "[redacted]",
			"allowed_previous_salts": len(c.Pow.AllowedPreviousSalts),
			"modes": map[string]interface{}{
				"ip_bound": modeView(c.Pow.Modes.IPBound), "generic": modeView(c.Pow.Modes.Generic),
			},
		},
		"protection": map[string]interface{}{
			"protected_extensions": append([]string(nil), c.Protection.ProtectedExtensions...),
			"protected_paths":      append([]string(nil), c.Protection.ProtectedPaths...),
			"excluded_paths":       append([]string(nil), c.Protection.ExcludedPaths...),
		},
		"storage": map[string]interface{}{
			"driver": c.Storage.Driver, "counter_driver": c.Storage.CounterDriver,
			"postgres": map[string]interface{}{"dsn_configured": c.Storage.Postgres.DSN != "", "max_open_conns": c.Storage.Postgres.MaxOpenConns, "max_idle_conns": c.Storage.Postgres.MaxIdleConns},
			"redis":    map[string]interface{}{"addr": c.Storage.Redis.Addr, "db": c.Storage.Redis.DB, "key_prefix": c.Storage.Redis.KeyPrefix, "password_configured": c.Storage.Redis.Password != ""},
		},
		"risk_control": map[string]interface{}{
			"enabled":       c.RiskControl.Enabled,
			"pending":       map[string]interface{}{"enabled": boolValue(c.RiskControl.Pending.Enabled), "max_per_ip": c.RiskControl.Pending.MaxPerIP, "block_ttl": c.RiskControl.Pending.BlockTTL.String()},
			"counter_count": len(c.RiskControl.Counters), "chain_count": len(c.RiskControl.Chains),
		},
		"admin": map[string]interface{}{
			"enabled": c.Admin.Enabled, "listen": c.Admin.Listen, "allow_cidrs": append([]string(nil), c.Admin.AllowCIDRs...),
			"auth":              map[string]interface{}{"type": c.Admin.Auth.Type, "token_configured": c.Admin.Auth.Token != "" || c.Admin.Auth.TokenFile != "", "username_configured": c.Admin.Auth.Username != "", "password_configured": c.Admin.Auth.Password != ""},
			"audit_log":         boolValue(c.Admin.AuditLog),
			"mutations_enabled": c.Admin.MutationsEnabled,
			"ip_block":          map[string]interface{}{"enabled": c.Admin.IPBlock.Enabled, "default_ttl": c.Admin.IPBlock.DefaultTTL.String(), "max_ttl": c.Admin.IPBlock.MaxTTL.String()},
			"config_management": map[string]interface{}{"enabled": c.Admin.ConfigManagement.Enabled},
			"stats":             map[string]interface{}{"prometheus_configured": c.Admin.Stats.PrometheusURL != "", "loki_configured": c.Admin.Stats.LokiURL != "", "query_timeout": c.Admin.Stats.QueryTimeout.String()},
		},
		"logging": map[string]interface{}{"level": c.Logging.Level, "format": c.Logging.Format, "log_access": boolValue(c.Logging.LogAccess), "log_denied": boolValue(c.Logging.LogDenied), "hash_ip": c.Logging.HashIP, "log_salt": "[redacted]"},
		"cleanup": map[string]interface{}{"enabled": boolValue(c.Cleanup.Enabled), "interval": c.Cleanup.Interval.String(), "expired_grace_period": c.Cleanup.ExpiredGracePeriod.String()},
	}
	result := ConfigGetResponse{Config: configView, Capabilities: ConfigCapabilities{}}
	if s.configState != nil {
		status := s.configState.Status()
		result.Managed = status.Managed
		result.CurrentRevision = status.CurrentRevision
		result.PendingRestart = status.PendingRestart
		result.Capabilities = ConfigCapabilities{
			Managed:          status.Managed,
			MutationsEnabled: c.Admin.MutationsEnabled,
			ApplyEnabled: status.Managed && c.Admin.MutationsEnabled && c.Admin.ConfigManagement.Enabled &&
				(c.Admin.Auth.Type == "token" || c.Admin.Auth.Type == "basic"),
			HistoryEnabled: status.Managed,
		}
		_, raw, err := s.configState.Current()
		if err == nil {
			result.EditableYAML = redactYAML(raw)
		}
	}
	return result, nil
}

func (s *Service) RuleList(_ context.Context, _ RuleListRequest) (RuleListResponse, error) {
	result := RuleListResponse{Chains: []RuleChainDTO{}}
	if s.cfg == nil {
		return result, nil
	}
	result.RiskControlEnabled = s.cfg.RiskControl.Enabled
	names := make([]string, 0, len(s.cfg.RiskControl.Chains))
	for name := range s.cfg.RiskControl.Chains {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		chain := s.cfg.RiskControl.Chains[name]
		dto := RuleChainDTO{
			Name:   name,
			Policy: DecisionDTO{Target: chain.Policy.Target, StatusCode: chain.Policy.Status, LimitRate: chain.Policy.LimitRate, Reason: chain.Policy.Reason, Chain: name},
			Rules:  []RuleItemDTO{},
		}
		for _, rule := range chain.Rules {
			dto.Rules = append(dto.Rules, RuleItemDTO{Name: rule.Name, Match: matchView(rule.Match), Target: rule.Target, Chain: rule.Chain, Status: rule.Status, LimitRate: rule.LimitRate, Reason: rule.Reason, Mark: rule.Mark})
		}
		result.Chains = append(result.Chains, dto)
	}
	return result, nil
}

func (s *Service) TokenGet(ctx context.Context, req TokenGetRequest) (TokenGetResponse, error) {
	result := TokenGetResponse{}
	if strings.TrimSpace(req.SignID) == "" {
		return result, errors.New("sign_id is required")
	}
	if len(req.SignID) > 128 {
		return result, errors.New("sign_id is too long")
	}
	if s.usage == nil {
		return result, errors.New("usage store is not configured")
	}
	record, err := s.usage.Get(ctx, req.SignID)
	if errors.Is(err, storage.ErrNotFound) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Found = true
	result.Token = TokenRecordDTO{ID: record.ID, Mode: record.Mode, Path: record.Path, Uses: record.Uses, MaxUses: record.MaxUses, ExpiresAt: record.ExpiresAt, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, IPHint: redactIP(record.LastIP)}
	return result, nil
}

func (s *Service) PendingList(_ context.Context, _ PendingListRequest) (PendingListResponse, error) {
	result := PendingListResponse{
		Scope:            "instance",
		MutationsEnabled: s.ipBlockMutationsEnabled(),
		Entries:          []PendingEntryDTO{},
	}
	if s.pending == nil {
		return result, nil
	}
	for _, item := range s.pending.Snapshot() {
		result.Entries = append(result.Entries, pendingEntryDTO(item))
	}
	return result, nil
}

func (s *Service) ipBlockMutationsEnabled() bool {
	return s.cfg != nil && s.cfg.Admin.MutationsEnabled && s.cfg.Admin.IPBlock.Enabled &&
		(s.cfg.Admin.Auth.Type == "token" || s.cfg.Admin.Auth.Type == "basic") && s.ipBlocks != nil
}

func pendingEntryDTO(item risk.PendingSnapshot) PendingEntryDTO {
	entry := PendingEntryDTO{
		IP:      redactIP(item.IP),
		Pending: item.Pending,
		Blocked: item.Blocked,
		Source:  item.Source,
		Reason:  item.Reason,
		Actor:   item.Actor,
	}
	if !item.BlockedUntil.IsZero() {
		entry.BlockedUntil = item.BlockedUntil.Unix()
	}
	if !item.CreatedAt.IsZero() {
		entry.CreatedAt = item.CreatedAt.Unix()
	}
	if !item.UpdatedAt.IsZero() {
		entry.UpdatedAt = item.UpdatedAt.Unix()
	}
	return entry
}

func (s *Service) AuditList(ctx context.Context, req AuditListRequest) (AuditListResponse, error) {
	result := AuditListResponse{Available: false, Events: []AuditEventDTO{}}
	if s.loki == nil {
		result.Error = "loki is not configured"
		return result, nil
	}
	events, err := s.loki.queryAudit(ctx, req)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	result.Available = true
	result.Events = events
	return result, nil
}

func (s *Service) queryTimeout() time.Duration {
	if s.cfg != nil && s.cfg.Admin.Stats.QueryTimeout > 0 {
		return s.cfg.Admin.Stats.QueryTimeout
	}
	return 2 * time.Second
}

func runExternalProbe(parent context.Context, name string, check func(context.Context) error, timeout time.Duration) SourceStatus {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	started := time.Now()
	status := SourceStatus{Name: name, Status: "ok"}
	if err := check(ctx); err != nil {
		status.Status = "error"
		status.Detail = err.Error()
	}
	status.Latency = time.Since(started).Milliseconds()
	return status
}

func boolValue(value *bool) bool {
	return value == nil || *value
}

func modeView(mode config.ModeConfig) map[string]interface{} {
	return map[string]interface{}{"enabled": mode.Enabled, "min_difficulty": mode.MinDifficulty, "max_difficulty": mode.MaxDifficulty, "max_ttl_seconds": mode.MaxTTLSeconds, "require_ip": mode.RequireIP, "max_uses": mode.MaxUses, "count_head_request": mode.CountHeadRequest}
}

func matchView(match config.MatchConfig) map[string]interface{} {
	result := map[string]interface{}{}
	if match.PathRegex != "" {
		result["path_regex"] = match.PathRegex
	}
	if match.PathPrefix != "" {
		result["path_prefix"] = match.PathPrefix
	}
	if len(match.ExtensionIn) > 0 {
		result["extension_in"] = append([]string(nil), match.ExtensionIn...)
	}
	if len(match.MethodIn) > 0 {
		result["method_in"] = append([]string(nil), match.MethodIn...)
	}
	if len(match.IPCIDRIn) > 0 {
		result["ip_cidr_in"] = append([]string(nil), match.IPCIDRIn...)
	}
	if match.UserAgentRegex != "" {
		result["user_agent_regex"] = match.UserAgentRegex
	}
	if match.PowStatus != "" {
		result["pow_status"] = match.PowStatus
	}
	if len(match.PowStatusIn) > 0 {
		result["pow_status_in"] = append([]string(nil), match.PowStatusIn...)
	}
	if match.PowMode != "" {
		result["pow_mode"] = match.PowMode
	}
	if match.IsProtected != nil {
		result["is_protected"] = *match.IsProtected
	}
	if match.IsRangeRequest != nil {
		result["is_range_request"] = *match.IsRangeRequest
	}
	if match.Counter != nil {
		result["counter"] = map[string]interface{}{"name": match.Counter.Name, "op": match.Counter.Op, "value": match.Counter.Value}
	}
	return result
}

func redactIP(ip string) string {
	return FingerprintIP(ip)
}

// FingerprintIP returns the non-reversible short identifier used in Admin API
// responses and audit events. It never returns the raw input.
func FingerprintIP(ip string) string {
	if canonical, err := risk.CanonicalIP(ip); err == nil {
		ip = canonical
	}
	if ip == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])[:12]
}

var _ UsageReader = (storage.UsageStore)(nil)
var _ PendingSnapshotSource = (*risk.IPPendingBlocker)(nil)
var _ IPBlockAdmin = (*risk.IPPendingBlocker)(nil)
