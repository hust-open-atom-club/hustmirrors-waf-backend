// Package configctl provides the local, in-process configuration
// management workflow shared by the garmr CLI: candidate validation,
// secret placeholder merging, danger-classified diffs and audited
// apply/rollback via the configstore history.
package configctl

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/configstore"
)

const maxCandidateBytes = 128 << 10

// DiffChange is one leaf-level difference between two configurations.
type DiffChange struct {
	Path            string
	Kind            string
	Before          interface{}
	After           interface{}
	Sensitive       bool
	Danger          string
	RestartRequired bool
}

// Plan describes what applying a candidate would do.
type Plan struct {
	BaseRevision uint64
	Changes      []DiffChange
	Danger       string
	Phrase       string // non-empty when confirmation is required
}

// ConfirmationRequired reports whether the caller must echo Phrase back
// before applying.
func (p Plan) ConfirmationRequired() bool { return p.Phrase != "" }

// Manager owns the configstore for a single configuration file and the
// workflows around it. It is intended for short-lived CLI processes:
// open, do work, close.
type Manager struct {
	store *configstore.Store
	path  string
}

// Open loads the configuration file at path and attaches a managed store
// (history lives next to the file in .mirrors-waf-history/).
func Open(path string) (*Manager, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	store, err := configstore.New(path, raw, true)
	if err != nil {
		return nil, err
	}
	return &Manager{store: store, path: path}, nil
}

// Path returns the configuration file path.
func (m *Manager) Path() string { return m.path }

// Status returns the store status snapshot.
func (m *Manager) Status() configstore.Status { return m.store.Status() }

// Current returns the active revision and its raw (unredacted) bytes.
func (m *Manager) Current() (uint64, []byte, error) { return m.store.Current() }

// Redacted returns the current configuration with sensitive values
// replaced by ${SECRET:KEEP} placeholders.
func (m *Manager) Redacted() (uint64, string, error) {
	rev, raw, err := m.store.Current()
	if err != nil {
		return 0, "", err
	}
	return rev, RedactYAML(raw), nil
}

// ValidateYAML parses and validates a candidate configuration, returning
// the list of problems (empty when valid).
func ValidateYAML(raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > maxCandidateBytes {
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

// MergeSecrets replaces ${SECRET:KEEP} placeholders in the edited text
// with the real values from the currently active configuration and
// rejects suspicious literal edits of sensitive fields.
func (m *Manager) MergeSecrets(edited string) ([]byte, error) {
	_, current, err := m.store.Current()
	if err != nil {
		return nil, err
	}
	return mergeSecretPlaceholders(edited, current)
}

// Plan diffs a candidate (raw, secrets already merged) against the active
// configuration and classifies the danger.
func (m *Manager) Plan(raw []byte, action string) (Plan, error) {
	baseRevision, baseRaw, err := m.store.Current()
	if err != nil {
		return Plan{}, err
	}
	changes, danger, _ := Diff(baseRaw, raw)
	if len(changes) == 0 {
		return Plan{BaseRevision: baseRevision, Changes: changes, Danger: "normal"}, nil
	}
	plan := Plan{BaseRevision: baseRevision, Changes: changes, Danger: danger}
	if danger != "normal" || action == "rollback" {
		plan.Phrase = strings.ToUpper(action) + " " + confirmToken(8)
	}
	return plan, nil
}

// PlanRollback builds a plan for restoring a historical revision.
func (m *Manager) PlanRollback(revision uint64) (Plan, configstore.Revision, error) {
	target, err := m.store.HistoryGet(revision)
	if err != nil {
		return Plan{}, configstore.Revision{}, err
	}
	if problems, validateErr := ValidateYAML(target.Raw); validateErr != nil || len(problems) > 0 {
		return Plan{}, configstore.Revision{}, fmt.Errorf("revision %d no longer validates", revision)
	}
	plan, err := m.Plan(target.Raw, "rollback")
	if err != nil {
		return Plan{}, configstore.Revision{}, err
	}
	return plan, target, nil
}

// Apply atomically writes the candidate (secrets already merged), records
// a history revision and returns the result.
func (m *Manager) Apply(raw []byte, plan Plan, reason, actor, action string, rollbackTarget uint64) (configstore.ApplyResult, error) {
	reason, err := validateReason(reason, plan.Danger != "normal" || action == "rollback")
	if err != nil {
		return configstore.ApplyResult{}, err
	}
	return m.store.Apply(configstore.ApplyRequest{
		Raw: raw, ExpectedRevision: plan.BaseRevision, Actor: actor, Reason: reason,
		Changed: len(plan.Changes), Danger: plan.Danger, RestartRequired: true,
		Action: action, RollbackTarget: rollbackTarget,
	})
}

// History lists recent revision metadata, newest first.
func (m *Manager) History(limit int) ([]configstore.RevisionMeta, error) {
	return m.store.History(limit)
}

// HistoryGet returns one historical revision including its raw bytes.
func (m *Manager) HistoryGet(revision uint64) (configstore.Revision, error) {
	return m.store.HistoryGet(revision)
}

// validateReason trims and sanity-checks the recorded change reason.
func validateReason(value string, required bool) (string, error) {
	reason := strings.TrimSpace(value)
	if required && reason == "" {
		return "", fmt.Errorf("reason is required for this change")
	}
	if len(reason) > 256 {
		return "", fmt.Errorf("reason is too long")
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("reason must not contain control characters")
		}
	}
	return reason, nil
}

// Diff computes leaf-level changes between two YAML documents and
// classifies each one. Sensitive values are blanked in the result.
func Diff(before, after []byte) (changes []DiffChange, danger string, restart bool) {
	var oldNode, newNode interface{}
	if len(before) > 0 {
		_ = yaml.Unmarshal(before, &oldNode)
	}
	if len(after) > 0 {
		_ = yaml.Unmarshal(after, &newNode)
	}
	diffValue("", normalizeYAML(oldNode), normalizeYAML(newNode), &changes)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	danger = "normal"
	for i := range changes {
		changes[i].Sensitive = isSensitivePath(changes[i].Path)
		if changes[i].Sensitive {
			changes[i].Before, changes[i].After = nil, nil
		}
		changes[i].Danger, _ = classifyChange(changes[i].Path, changes[i].Before, changes[i].After)
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

func diffValue(path string, before, after interface{}, out *[]DiffChange) {
	if equalValue(before, after) {
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
	*out = append(*out, DiffChange{Path: path, Kind: kind, Before: before, After: after})
}

func classifyChange(path string, before, after interface{}) (danger string, restart bool) {
	lower := strings.ToLower(path)
	restart = strings.HasPrefix(lower, "server.") || strings.HasPrefix(lower, "storage.") || strings.HasPrefix(lower, "cleanup.") ||
		lower == "logging.level" || lower == "logging.format" ||
		strings.HasPrefix(lower, "risk_control.pending.max_per_ip") || strings.HasPrefix(lower, "risk_control.pending.block_ttl")
	danger = "normal"
	if strings.Contains(lower, "bypass_all") || strings.Contains(lower, "enabled") || strings.Contains(lower, "excluded") || strings.HasPrefix(lower, "protection.") || isSensitivePath(path) {
		danger = "dangerous"
	}
	if strings.Contains(lower, "bypass_all") || strings.HasSuffix(lower, "pow.enabled") || strings.HasSuffix(lower, "risk_control.enabled") ||
		strings.Contains(lower, "allow_empty_salt") || difficultyReduced(lower, before, after) {
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

// phraseMatches is kept for library consumers that pre-validate the
// confirmation phrase programmatically.
func (p Plan) phraseMatches(input string) bool { return input != "" && input == p.Phrase }

func confirmToken(n int) string {
	b := make([]byte, n)
	if _, err := readRandom(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, n)
	for i, v := range b {
		out[i] = hexDigits[v&0xf]
	}
	return string(out)
}

// HistoryDirName is the directory (next to the config file) that stores
// revision history.
func HistoryDirName() string { return ".mirrors-waf-history" }

// AbsPath resolves the configuration path, used by the CLI for messages.
func AbsPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
