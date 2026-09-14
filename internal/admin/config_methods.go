package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/configstore"
)

const maxConfigCandidateBytes = 128 << 10

type configPreview struct {
	ID              string
	CreatedAt       time.Time
	DraftID         string
	DraftRevision   uint64
	BaseRevision    uint64
	TargetRevision  uint64
	Raw             []byte
	Changes         []ConfigDiffChange
	Danger          string
	RestartRequired bool
	Phrase          string
}

func (s *Service) configMutationAccess() error {
	if s.cfg == nil || !s.cfg.Admin.MutationsEnabled {
		return MutationsDisabledError()
	}
	if s.cfg.Admin.Auth.Token == "" {
		return MutationAuthRequiredError()
	}
	if !s.cfg.Admin.ConfigManagement.Enabled {
		return ConfigWritesDisabledError()
	}
	if s.configState == nil {
		return ConfigSourceUnmanagedError()
	}
	return nil
}

func (s *Service) ConfigStatus(_ context.Context, _ ConfigStatusRequest) (ConfigStatusResponse, error) {
	result := ConfigStatusResponse{Capabilities: ConfigCapabilities{}}
	if s.configState == nil {
		result.Capabilities.MutationsEnabled = s.cfg != nil && s.cfg.Admin.MutationsEnabled
		return result, nil
	}
	status := s.configState.Status()
	result.Managed = status.Managed
	result.CurrentRevision = status.CurrentRevision
	result.PendingRestart = status.PendingRestart
	result.Capabilities = ConfigCapabilities{
		Managed:          status.Managed,
		MutationsEnabled: s.cfg != nil && s.cfg.Admin.MutationsEnabled,
		ApplyEnabled: status.Managed && s.cfg != nil && s.cfg.Admin.MutationsEnabled &&
			s.cfg.Admin.ConfigManagement.Enabled && s.cfg.Admin.Auth.Token != "",
		HistoryEnabled: status.Managed,
	}
	if status.Draft != nil {
		result.Draft = &DraftSummary{
			ID: status.Draft.ID, Revision: status.Draft.Revision,
			BaseRevision: status.Draft.BaseRevision,
			UpdatedAt:    status.Draft.UpdatedAt.Unix(),
			Validated:    status.Draft.Validated,
		}
	}
	return result, nil
}

func (s *Service) ConfigDraftSave(_ context.Context, req ConfigDraftSaveRequest) (ConfigDraftResponse, error) {
	if err := s.configMutationAccess(); err != nil {
		return ConfigDraftResponse{}, err
	}
	if len(req.ConfigYAML) == 0 {
		return ConfigDraftResponse{}, ValidationError("config candidate is empty")
	}
	if len(req.ConfigYAML) > maxConfigCandidateBytes {
		return ConfigDraftResponse{}, ConfigTooLargeError()
	}
	secretBase := s.currentRaw()
	if req.DraftID != "" {
		existing, getErr := s.configState.GetDraft(req.DraftID)
		if getErr != nil {
			return ConfigDraftResponse{}, mapConfigStateError(getErr)
		}
		secretBase = existing.Raw
	}
	raw, err := mergeSecretPlaceholders(req.ConfigYAML, secretBase)
	if err != nil {
		return ConfigDraftResponse{}, err
	}
	if err := config.ValidateYAMLStructure(raw); err != nil {
		return ConfigDraftResponse{}, ValidationError("candidate YAML structure is invalid")
	}
	draft, err := s.configState.SaveDraft(req.BaseRevision, req.DraftID, req.ExpectedDraftRevision, raw)
	if err != nil {
		return ConfigDraftResponse{}, mapConfigStateError(err)
	}
	return draftResponse(draft), nil
}

func (s *Service) ConfigDraftGet(_ context.Context, req ConfigDraftGetRequest) (ConfigDraftResponse, error) {
	if s.configState == nil {
		return ConfigDraftResponse{}, ConfigSourceUnmanagedError()
	}
	draft, err := s.configState.GetDraft(req.DraftID)
	if err != nil {
		return ConfigDraftResponse{}, mapConfigStateError(err)
	}
	return draftResponse(draft), nil
}

func (s *Service) ConfigDraftDiscard(_ context.Context, req ConfigDraftDiscardRequest) (ConfigDraftResponse, error) {
	if err := s.configMutationAccess(); err != nil {
		return ConfigDraftResponse{}, err
	}
	if err := s.configState.DiscardDraft(req.DraftID, req.ExpectedDraftRevision); err != nil {
		return ConfigDraftResponse{}, mapConfigStateError(err)
	}
	return ConfigDraftResponse{}, nil
}

func (s *Service) ConfigValidate(_ context.Context, req ConfigValidateRequest) (ConfigValidateResponse, error) {
	var raw []byte
	var draftID string
	var draftRevision uint64
	if req.DraftID != "" {
		if s.configState == nil {
			return ConfigValidateResponse{}, ConfigSourceUnmanagedError()
		}
		draft, err := s.configState.GetDraft(req.DraftID)
		if err != nil {
			return ConfigValidateResponse{}, mapConfigStateError(err)
		}
		if req.DraftRevision == 0 || req.DraftRevision != draft.Revision {
			return ConfigValidateResponse{}, DraftConflictError()
		}
		raw = draft.Raw
		draftID = draft.ID
		draftRevision = draft.Revision
	} else {
		raw = []byte(req.ConfigYAML)
	}
	problems, err := validateCandidate(raw)
	if err != nil {
		return ConfigValidateResponse{Valid: false, Error: "candidate configuration could not be parsed"}, nil
	}
	if draftID != "" && len(problems) == 0 {
		if err := s.configState.MarkDraftValidated(draftID, draftRevision, draftRevision); err != nil {
			return ConfigValidateResponse{}, mapConfigStateError(err)
		}
	}
	return ConfigValidateResponse{OK: len(problems) == 0, Valid: len(problems) == 0, Problems: problems, DraftID: draftID, DraftRevision: draftRevision, RestartRequired: true}, nil
}

func (s *Service) ConfigDiff(_ context.Context, req ConfigDiffRequest) (ConfigDiffResponse, error) {
	if s.configState == nil {
		return ConfigDiffResponse{}, ConfigSourceUnmanagedError()
	}
	baseRevision, baseRaw, err := s.configState.Current()
	if err != nil {
		return ConfigDiffResponse{}, ConfigPersistError()
	}

	preview := configPreview{BaseRevision: baseRevision, CreatedAt: time.Now()}
	candidateRevision := uint64(0)
	phrasePrefix := "APPLY "
	if req.TargetRevision > 0 {
		target, err := s.configState.HistoryGet(req.TargetRevision)
		if err != nil {
			return ConfigDiffResponse{}, mapConfigStateError(err)
		}
		preview.TargetRevision = req.TargetRevision
		if problems, validateErr := validateCandidate(target.Raw); validateErr != nil || len(problems) > 0 {
			return ConfigDiffResponse{}, ConfigInvalidError()
		}
		preview.Raw = append([]byte(nil), target.Raw...)
		candidateRevision = req.TargetRevision
		phrasePrefix = "ROLLBACK "
	} else {
		draft, err := s.configState.GetDraft(req.DraftID)
		if err != nil {
			return ConfigDiffResponse{}, mapConfigStateError(err)
		}
		if req.DraftRevision == 0 || req.DraftRevision != draft.Revision || !draft.Validated {
			return ConfigDiffResponse{}, ValidationRequiredError()
		}
		if draft.BaseRevision != baseRevision {
			return ConfigDiffResponse{}, ConfigConflictError()
		}
		preview.DraftID = draft.ID
		preview.DraftRevision = draft.Revision
		preview.Raw = append([]byte(nil), draft.Raw...)
		candidateRevision = draft.Revision
	}

	changes, danger, restart := diffYAML(baseRaw, preview.Raw)
	if len(changes) == 0 {
		return ConfigDiffResponse{BaseRevision: baseRevision, CandidateRevision: candidateRevision, Changes: []ConfigDiffChange{}, Danger: "normal"}, nil
	}
	id := randomPreviewID()
	phrase := ""
	if danger != "normal" || req.TargetRevision > 0 {
		phrase = phrasePrefix + id[:8]
	}
	preview.ID = id
	preview.Changes = changes
	preview.Danger = danger
	preview.RestartRequired = restart
	preview.Phrase = phrase
	s.previewMu.Lock()
	s.previews[id] = preview
	s.previewMu.Unlock()
	return ConfigDiffResponse{PreviewID: id, BaseRevision: baseRevision, CandidateRevision: candidateRevision, Changes: changes, Danger: danger, RestartRequired: restart, ConfirmationPhrase: phrase}, nil
}

func (s *Service) ConfigApply(_ context.Context, req ConfigApplyRequest) (ConfigApplyResponse, error) {
	if err := s.configMutationAccess(); err != nil {
		return ConfigApplyResponse{}, err
	}
	preview, err := s.getPreview(req.PreviewID)
	if err != nil {
		return ConfigApplyResponse{}, err
	}
	if preview.TargetRevision != 0 || preview.DraftID != req.DraftID || preview.DraftRevision != req.DraftRevision || preview.BaseRevision != req.ExpectedRevision {
		return ConfigApplyResponse{}, PreviewStaleError()
	}
	currentDraft, err := s.configState.GetDraft(req.DraftID)
	if err != nil || currentDraft.Revision != preview.DraftRevision || !currentDraft.Validated {
		return ConfigApplyResponse{}, PreviewStaleError()
	}
	if !req.Acknowledged {
		return ConfigApplyResponse{}, ConfirmationRequiredError()
	}
	reason, err := validateConfigReason(req.Reason, preview.Danger != "normal")
	if err != nil {
		return ConfigApplyResponse{}, err
	}
	if preview.Danger != "normal" && req.ConfirmationPhrase != preview.Phrase {
		return ConfigApplyResponse{}, ConfirmationInvalidError()
	}
	result, err := s.configState.Apply(configstore.ApplyRequest{Raw: preview.Raw, ExpectedRevision: preview.BaseRevision, Actor: req.Actor, Reason: reason, Changed: len(preview.Changes), Danger: preview.Danger, RestartRequired: true, Action: "apply"})
	if err != nil {
		return ConfigApplyResponse{}, mapConfigStateError(err)
	}
	s.deletePreview(req.PreviewID)
	return ConfigApplyResponse{PreviousRevision: result.Previous, Revision: result.Revision, ChangeCount: len(preview.Changes), Danger: preview.Danger, RuntimeApplied: false, RestartRequired: true}, nil
}

func (s *Service) ConfigHistory(_ context.Context, req ConfigHistoryRequest) (ConfigHistoryResponse, error) {
	if s.configState == nil {
		return ConfigHistoryResponse{}, ConfigSourceUnmanagedError()
	}
	items, err := s.configState.History(req.Limit)
	if err != nil {
		return ConfigHistoryResponse{}, mapConfigStateError(err)
	}
	result := ConfigHistoryResponse{Entries: make([]ConfigHistoryEntry, 0, len(items))}
	for _, item := range items {
		result.Entries = append(result.Entries, historyEntry(item))
	}
	return result, nil
}

func (s *Service) ConfigHistoryGet(_ context.Context, req ConfigHistoryGetRequest) (ConfigHistoryGetResponse, error) {
	if s.configState == nil {
		return ConfigHistoryGetResponse{}, ConfigSourceUnmanagedError()
	}
	item, err := s.configState.HistoryGet(req.Revision)
	if err != nil {
		return ConfigHistoryGetResponse{}, mapConfigStateError(err)
	}
	return ConfigHistoryGetResponse{Revision: historyEntry(item.Meta), ConfigYAML: redactYAML(item.Raw)}, nil
}

func (s *Service) ConfigRollback(_ context.Context, req ConfigRollbackRequest) (ConfigRollbackResponse, error) {
	if err := s.configMutationAccess(); err != nil {
		return ConfigRollbackResponse{}, err
	}
	preview, err := s.getPreview(req.PreviewID)
	if err != nil {
		return ConfigRollbackResponse{}, err
	}
	if preview.TargetRevision == 0 || preview.TargetRevision != req.TargetRevision || preview.BaseRevision != req.ExpectedRevision {
		return ConfigRollbackResponse{}, PreviewStaleError()
	}
	if !req.Acknowledged {
		return ConfigRollbackResponse{}, ConfirmationRequiredError()
	}
	reason, err := validateConfigReason(req.Reason, true)
	if err != nil {
		return ConfigRollbackResponse{}, err
	}
	if req.ConfirmationPhrase != preview.Phrase {
		return ConfigRollbackResponse{}, ConfirmationInvalidError()
	}
	result, err := s.configState.Apply(configstore.ApplyRequest{Raw: preview.Raw, ExpectedRevision: preview.BaseRevision, Actor: req.Actor, Reason: reason, Changed: len(preview.Changes), Danger: preview.Danger, RestartRequired: true, Action: "rollback", RollbackTarget: req.TargetRevision})
	if err != nil {
		return ConfigRollbackResponse{}, mapConfigStateError(err)
	}
	s.deletePreview(req.PreviewID)
	return ConfigRollbackResponse{PreviousRevision: result.Previous, Revision: result.Revision, ChangeCount: len(preview.Changes), Danger: preview.Danger, RuntimeApplied: false, RestartRequired: true}, nil
}

func draftResponse(d configstore.Draft) ConfigDraftResponse {
	return ConfigDraftResponse{DraftID: d.ID, DraftRevision: d.Revision, BaseRevision: d.BaseRevision, UpdatedAt: d.UpdatedAt.Unix(), ConfigYAML: redactYAML(d.Raw), Validated: d.Validated}
}

func historyEntry(m configstore.RevisionMeta) ConfigHistoryEntry {
	return ConfigHistoryEntry{Revision: m.Revision, ParentRevision: m.ParentRevision, Action: m.Action, Actor: m.Actor, Reason: m.Reason, RollbackTarget: m.RollbackTarget, Changed: m.Changed, Danger: m.Danger, RestartRequired: m.RestartRequired, CreatedAt: m.CreatedAt.Unix()}
}

func mapConfigStateError(err error) error {
	switch {
	case errors.Is(err, configstore.ErrUnmanaged):
		return ConfigSourceUnmanagedError()
	case errors.Is(err, configstore.ErrConflict):
		return ConfigConflictError()
	case errors.Is(err, configstore.ErrDraftNotFound):
		return DraftNotFoundError()
	case errors.Is(err, configstore.ErrDraftExpired):
		return DraftExpiredError()
	case errors.Is(err, configstore.ErrDraftConflict):
		return DraftConflictError()
	case errors.Is(err, configstore.ErrRevisionNotFound):
		return HistoryNotFoundError()
	case errors.Is(err, configstore.ErrTooLarge):
		return ConfigTooLargeError()
	default:
		return ConfigPersistError()
	}
}

func validateCandidate(raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > maxConfigCandidateBytes {
		return nil, fmt.Errorf("invalid candidate size")
	}
	cfg, err := config.LoadRawFromBytes(raw)
	if err != nil {
		return nil, err
	}
	config.ApplyDefaults(cfg)
	if err := config.Validate(cfg); err != nil {
		if ve, ok := err.(config.ValidationError); ok {
			return ve.Problems, nil
		}
		return nil, err
	}
	return nil, nil
}

func (s *Service) currentRaw() []byte {
	if s.configState == nil {
		return nil
	}
	_, raw, _ := s.configState.Current()
	return raw
}

func randomPreviewID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func (s *Service) getPreview(id string) (configPreview, error) {
	s.previewMu.Lock()
	defer s.previewMu.Unlock()
	item, ok := s.previews[id]
	if !ok {
		return configPreview{}, PreviewStaleError()
	}
	if time.Since(item.CreatedAt) > 10*time.Minute {
		delete(s.previews, id)
		return configPreview{}, PreviewExpiredError()
	}
	return item, nil
}

func (s *Service) deletePreview(id string) {
	s.previewMu.Lock()
	delete(s.previews, id)
	s.previewMu.Unlock()
}

func validateConfigReason(value string, required bool) (string, error) {
	reason := strings.TrimSpace(value)
	if required && reason == "" {
		return "", ValidationError("reason is required for configuration changes")
	}
	if len(reason) > 256 {
		return "", ValidationError("reason is too long")
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f {
			return "", ValidationError("reason must not contain control characters")
		}
	}
	return reason, nil
}

func diffYAML(before, after []byte) ([]ConfigDiffChange, string, bool) {
	var oldNode, newNode interface{}
	if len(before) > 0 {
		_ = yaml.Unmarshal(before, &oldNode)
	}
	if len(after) > 0 {
		_ = yaml.Unmarshal(after, &newNode)
	}
	oldMap := normalizeYAML(oldNode)
	newMap := normalizeYAML(newNode)
	changes := make([]ConfigDiffChange, 0)
	diffValue("", oldMap, newMap, &changes)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	danger := "normal"
	restart := false
	for i := range changes {
		changes[i].Sensitive = isSensitivePath(changes[i].Path)
		if changes[i].Sensitive {
			changes[i].Before, changes[i].After = nil, nil
		}
		changes[i].Danger, _ = classifyConfigChange(changes[i].Path, changes[i].Before, changes[i].After)
		changes[i].RestartRequired = true
		restart = true
		if dangerRank(changes[i].Danger) > dangerRank(danger) {
			danger = changes[i].Danger
		}
	}
	return changes, danger, restart
}

func normalizeYAML(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, item := range v {
			out[k] = normalizeYAML(item)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, item := range v {
			out[fmt.Sprint(k)] = normalizeYAML(item)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = normalizeYAML(item)
		}
		return out
	default:
		return v
	}
}

func diffValue(path string, before, after interface{}, out *[]ConfigDiffChange) {
	if reflect.DeepEqual(before, after) {
		return
	}
	bm, bok := before.(map[string]interface{})
	am, aok := after.(map[string]interface{})
	if bok && aok {
		keys := map[string]struct{}{}
		for k := range bm {
			keys[k] = struct{}{}
		}
		for k := range am {
			keys[k] = struct{}{}
		}
		ordered := make([]string, 0, len(keys))
		for k := range keys {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			p := key
			if path != "" {
				p = path + "." + key
			}
			diffValue(p, bm[key], am[key], out)
		}
		return
	}
	kind := "changed"
	if before == nil {
		kind = "added"
	}
	if after == nil {
		kind = "removed"
	}
	*out = append(*out, ConfigDiffChange{Path: path, Kind: kind, Before: before, After: after})
}

var sensitiveConfigPaths = map[string]struct{}{
	"pow.public_salt":            {},
	"pow.allowed_previous_salts": {},
	"storage.postgres.dsn":       {},
	"storage.redis.password":     {},
	"admin.auth.token":           {},
	"admin.auth.token_file":      {},
	"admin.auth.password":        {},
	"admin.stats.prometheus_url": {},
	"admin.stats.loki_url":       {},
	"logging.log_salt":           {},
}

func isSensitivePath(path string) bool {
	_, ok := sensitiveConfigPaths[strings.ToLower(path)]
	return ok
}

func classifyConfigChange(path string, before, after interface{}) (string, bool) {
	lower := strings.ToLower(path)
	restart := strings.HasPrefix(lower, "server.") || strings.HasPrefix(lower, "storage.") || strings.HasPrefix(lower, "admin.") || strings.HasPrefix(lower, "cleanup.") || lower == "logging.level" || lower == "logging.format" || strings.HasPrefix(lower, "risk_control.pending.max_per_ip") || strings.HasPrefix(lower, "risk_control.pending.block_ttl")
	danger := "normal"
	if strings.Contains(lower, "bypass_all") || strings.Contains(lower, "enabled") || strings.Contains(lower, "excluded") || strings.HasPrefix(lower, "protection.") || isSensitivePath(path) {
		danger = "dangerous"
	}
	if strings.Contains(lower, "bypass_all") || strings.HasSuffix(lower, "pow.enabled") || strings.HasSuffix(lower, "risk_control.enabled") || strings.Contains(lower, "allow_empty_salt") || difficultyReduced(lower, before, after) {
		danger = "critical"
	}
	return danger, restart
}

func difficultyReduced(path string, before, after interface{}) bool {
	if !strings.Contains(path, "difficulty") {
		return false
	}
	oldValue, oldOK := numericValue(before)
	newValue, newOK := numericValue(after)
	return oldOK && newOK && newValue < oldValue
}

func numericValue(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

func dangerRank(value string) int {
	switch value {
	case "critical":
		return 3
	case "dangerous":
		return 2
	default:
		return 1
	}
}

func mergeSecretPlaceholders(raw string, current []byte) ([]byte, error) {
	if len(current) == 0 {
		return nil, SecretPlaceholderError()
	}
	var candidate, base map[string]interface{}
	if err := yaml.Unmarshal([]byte(raw), &candidate); err != nil {
		return nil, ValidationError("invalid YAML candidate")
	}
	if err := yaml.Unmarshal(current, &base); err != nil {
		return nil, SecretPlaceholderError()
	}
	if err := mergeSecretMap("", candidate, base); err != nil {
		return nil, err
	}
	out, err := yaml.Marshal(candidate)
	if err != nil {
		return nil, SecretPlaceholderError()
	}
	return out, nil
}

func mergeSecretMap(prefix string, candidate, base map[string]interface{}) error {
	for key, baseValue := range base {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		candidateValue, exists := candidate[key]
		if isSensitivePath(path) && !exists {
			return SecretPlaceholderError()
		}
		if baseChild, ok := baseValue.(map[string]interface{}); ok {
			candidateChild, _ := candidateValue.(map[string]interface{})
			if candidateChild == nil {
				candidateChild = map[string]interface{}{}
			}
			if err := mergeSecretMap(path, candidateChild, baseChild); err != nil {
				return err
			}
		}
	}
	for key, value := range candidate {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if isSensitivePath(path) {
			text, isText := value.(string)
			switch {
			case isText && text == "${SECRET:KEEP}":
				baseValue, ok := base[key]
				if !ok {
					return SecretPlaceholderError()
				}
				candidate[key] = baseValue
			case isText && text == "${SECRET:CLEAR}":
				candidate[key] = emptySecretValue(base[key])
			case reflect.DeepEqual(value, base[key]):
				// Accept an unchanged literal for CLI/API compatibility, but never
				// return it to the client.
			default:
				return SecretPlaceholderError()
			}
			continue
		}
		if text, ok := value.(string); ok && strings.HasPrefix(text, "${SECRET:") {
			return SecretPlaceholderError()
		}
		if child, ok := value.(map[string]interface{}); ok {
			if _, exists := base[key].(map[string]interface{}); !exists {
				if err := rejectSecretPlaceholderMap(path, child); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rejectSecretPlaceholderMap(prefix string, node map[string]interface{}) error {
	for key, value := range node {
		path := prefix + "." + key
		if isSensitivePath(path) {
			return SecretPlaceholderError()
		}
		if text, ok := value.(string); ok && strings.HasPrefix(text, "${SECRET:") {
			return SecretPlaceholderError()
		}
		if child, ok := value.(map[string]interface{}); ok {
			if err := rejectSecretPlaceholderMap(path, child); err != nil {
				return err
			}
		}
	}
	return nil
}

func emptySecretValue(value interface{}) interface{} {
	switch value.(type) {
	case []interface{}, []string:
		return []interface{}{}
	default:
		return ""
	}
}

func redactYAML(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var node map[string]interface{}
	if yaml.Unmarshal(raw, &node) != nil {
		return "# redacted configuration unavailable"
	}
	redactMap("", node)
	out, err := yaml.Marshal(node)
	if err != nil {
		return "# redacted configuration unavailable"
	}
	return string(out)
}

func redactMap(prefix string, node map[string]interface{}) {
	for key, value := range node {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if isSensitivePath(path) {
			node[key] = "${SECRET:KEEP}"
			continue
		}
		if child, ok := value.(map[string]interface{}); ok {
			redactMap(path, child)
		}
		if list, ok := value.([]interface{}); ok {
			for _, item := range list {
				if child, ok := item.(map[string]interface{}); ok {
					redactMap(path, child)
				}
			}
		}
	}
}
