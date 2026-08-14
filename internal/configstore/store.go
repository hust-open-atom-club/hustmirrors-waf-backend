package configstore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxDraftBytes  = 128 << 10
	historyDirName = ".mirrors-waf-history"
)

var (
	ErrUnmanaged        = errors.New("config store: source is unmanaged")
	ErrConflict         = errors.New("config store: configuration changed externally")
	ErrDraftNotFound    = errors.New("config store: draft not found")
	ErrDraftExpired     = errors.New("config store: draft expired")
	ErrDraftConflict    = errors.New("config store: draft revision conflict")
	ErrRevisionNotFound = errors.New("config store: revision not found")
	ErrInvalidRevision  = errors.New("config store: invalid revision")
	ErrTooLarge         = errors.New("config store: candidate is too large")
)

type Status struct {
	Managed          bool
	Path             string
	CurrentRevision  uint64
	CurrentUpdatedAt time.Time
	PendingRestart   bool
	Draft            *DraftSummary
}

type DraftSummary struct {
	ID           string    `json:"id"`
	Revision     uint64    `json:"revision"`
	BaseRevision uint64    `json:"base_revision"`
	UpdatedAt    time.Time `json:"updated_at"`
	Validated    bool      `json:"validated"`
	DiffRevision uint64    `json:"diff_revision,omitempty"`
}

type Draft struct {
	ID           string
	Revision     uint64
	BaseRevision uint64
	Raw          []byte
	UpdatedAt    time.Time
	Validated    bool
	DiffRevision uint64
}

type RevisionMeta struct {
	Revision        uint64    `json:"revision"`
	ParentRevision  uint64    `json:"parent_revision,omitempty"`
	Action          string    `json:"action"`
	Actor           string    `json:"actor,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	RollbackTarget  uint64    `json:"rollback_target,omitempty"`
	Changed         int       `json:"changed"`
	Danger          string    `json:"danger,omitempty"`
	RestartRequired bool      `json:"restart_required"`
	CreatedAt       time.Time `json:"created_at"`
}

type Revision struct {
	Meta RevisionMeta
	Raw  []byte
}

type ApplyRequest struct {
	Raw              []byte
	ExpectedRevision uint64
	Actor            string
	Reason           string
	Changed          int
	Danger           string
	RestartRequired  bool
	Action           string
	RollbackTarget   uint64
}

type ApplyResult struct {
	Revision        uint64
	Previous        uint64
	Meta            RevisionMeta
	RestartRequired bool
}

type Store struct {
	mu             sync.Mutex
	path           string
	managed        bool
	history        string
	raw            []byte
	revision       uint64
	updated        time.Time
	draft          *Draft
	pendingRestart bool
	now            func() time.Time
}

// New creates a single-instance configuration store. Unmanaged stores are
// read-only and never create directories or files.
func New(path string, raw []byte, managed bool) (*Store, error) {
	s := &Store{path: path, managed: managed, raw: append([]byte(nil), raw...), now: time.Now}
	if !managed {
		return s, nil
	}
	if strings.TrimSpace(path) == "" {
		return nil, ErrUnmanaged
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config store: resolve path: %w", err)
	}
	s.path = abs
	writable, err := os.OpenFile(abs, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("config store: source is not writable: %w", err)
	}
	if err := writable.Close(); err != nil {
		return nil, err
	}
	s.history = filepath.Join(filepath.Dir(abs), historyDirName)
	if err := os.MkdirAll(s.history, 0o700); err != nil {
		return nil, fmt.Errorf("config store: create history: %w", err)
	}
	if err := s.loadHistory(); err != nil {
		return nil, err
	}
	if s.revision == 0 {
		if err := s.writeRevisionLocked(RevisionMeta{Revision: 1, Action: "bootstrap", CreatedAt: s.now()}, s.raw); err != nil {
			return nil, err
		}
		s.revision = 1
		s.updated = s.now()
	} else {
		latest, err := os.ReadFile(filepath.Join(s.history, revisionName(s.revision)+".yaml"))
		if err != nil {
			return nil, err
		}
		if string(latest) != string(s.raw) {
			next := s.revision + 1
			meta := RevisionMeta{Revision: next, ParentRevision: s.revision, Action: "external", CreatedAt: s.now(), RestartRequired: false}
			if err := s.writeRevisionLocked(meta, s.raw); err != nil {
				return nil, err
			}
			s.revision = next
			s.updated = meta.CreatedAt
		}
	}
	return s, nil
}

func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := Status{Managed: s.managed, Path: s.path, CurrentRevision: s.revision, CurrentUpdatedAt: s.updated, PendingRestart: s.pendingRestart}
	if s.draft != nil {
		copy := draftSummary(*s.draft)
		status.Draft = &copy
	}
	return status
}

func (s *Store) Current() (uint64, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision, append([]byte(nil), s.raw...), nil
}

func (s *Store) SaveDraft(baseRevision uint64, id string, expectedRevision uint64, raw []byte) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.managed {
		return Draft{}, ErrUnmanaged
	}
	if len(raw) > maxDraftBytes {
		return Draft{}, ErrTooLarge
	}
	if baseRevision == 0 {
		baseRevision = s.revision
	}
	if baseRevision != s.revision {
		return Draft{}, ErrConflict
	}
	if s.draft != nil {
		if id == "" || id != s.draft.ID || expectedRevision != s.draft.Revision {
			return Draft{}, ErrDraftConflict
		}
	} else if id != "" {
		return Draft{}, ErrDraftNotFound
	}
	if id == "" {
		id = randomID()
	}
	revision := uint64(1)
	if s.draft != nil {
		revision = s.draft.Revision + 1
	}
	s.draft = &Draft{ID: id, Revision: revision, BaseRevision: baseRevision, Raw: append([]byte(nil), raw...), UpdatedAt: s.now()}
	return cloneDraft(*s.draft), nil
}

func (s *Store) GetDraft(id string) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draft == nil || (id != "" && s.draft.ID != id) {
		return Draft{}, ErrDraftNotFound
	}
	if s.now().Sub(s.draft.UpdatedAt) > 24*time.Hour {
		s.draft = nil
		return Draft{}, ErrDraftExpired
	}
	return cloneDraft(*s.draft), nil
}

func (s *Store) MarkDraftValidated(id string, revision, diffRevision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draft == nil || s.draft.ID != id {
		return ErrDraftNotFound
	}
	if s.draft.Revision != revision {
		return ErrDraftConflict
	}
	s.draft.Validated = true
	s.draft.DiffRevision = diffRevision
	return nil
}

func (s *Store) DiscardDraft(id string, expectedRevision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.managed {
		return ErrUnmanaged
	}
	if s.draft == nil || s.draft.ID != id {
		return ErrDraftNotFound
	}
	if expectedRevision != 0 && s.draft.Revision != expectedRevision {
		return ErrDraftConflict
	}
	s.draft = nil
	return nil
}

func (s *Store) Apply(req ApplyRequest) (ApplyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.managed {
		return ApplyResult{}, ErrUnmanaged
	}
	if err := s.checkExternalLocked(); err != nil {
		return ApplyResult{}, err
	}
	if req.ExpectedRevision != 0 && req.ExpectedRevision != s.revision {
		return ApplyResult{}, ErrConflict
	}
	if len(req.Raw) > maxDraftBytes {
		return ApplyResult{}, ErrTooLarge
	}
	previous := s.revision
	next := previous + 1
	meta := RevisionMeta{Revision: next, ParentRevision: previous, Action: req.Action, Actor: req.Actor, Reason: req.Reason, RollbackTarget: req.RollbackTarget, Changed: req.Changed, Danger: req.Danger, RestartRequired: req.RestartRequired, CreatedAt: s.now()}
	if meta.Action == "" {
		meta.Action = "apply"
	}
	if err := s.writeRevisionLocked(meta, req.Raw); err != nil {
		return ApplyResult{}, err
	}
	if err := atomicReplace(s.path, req.Raw, 0o600); err != nil {
		s.removeRevisionLocked(next)
		return ApplyResult{}, err
	}
	s.raw = append([]byte(nil), req.Raw...)
	s.revision = next
	s.updated = meta.CreatedAt
	s.pendingRestart = true
	s.draft = nil
	return ApplyResult{Revision: next, Previous: previous, Meta: meta, RestartRequired: req.RestartRequired}, nil
}

func (s *Store) History(limit int) ([]RevisionMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.managed {
		return []RevisionMeta{}, ErrUnmanaged
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	items, err := s.readMetasLocked()
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Revision > items[j].Revision })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (s *Store) HistoryGet(revision uint64) (Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.managed || revision == 0 {
		return Revision{}, ErrRevisionNotFound
	}
	meta, err := readMeta(filepath.Join(s.history, revisionName(revision)+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return Revision{}, ErrRevisionNotFound
		}
		return Revision{}, err
	}
	raw, err := os.ReadFile(filepath.Join(s.history, revisionName(revision)+".yaml"))
	if err != nil {
		return Revision{}, err
	}
	return Revision{Meta: meta, Raw: raw}, nil
}

func (s *Store) checkExternalLocked() error {
	if !s.managed {
		return ErrUnmanaged
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if string(raw) != string(s.raw) {
		return ErrConflict
	}
	return nil
}

func (s *Store) loadHistory() error {
	items, err := s.readMetasLocked()
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Revision > s.revision {
			s.revision = item.Revision
			s.updated = item.CreatedAt
		}
	}
	// Keep the exact active file bytes passed by the loader. The history
	// directory is metadata, not the source of truth when an operator edits
	// the file outside this process.
	return nil
}

func (s *Store) readMetasLocked() ([]RevisionMeta, error) {
	entries, err := os.ReadDir(s.history)
	if err != nil {
		return nil, err
	}
	items := make([]RevisionMeta, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		meta, err := readMeta(filepath.Join(s.history, entry.Name()))
		if err != nil {
			return nil, err
		}
		items = append(items, meta)
	}
	return items, nil
}

func (s *Store) removeRevisionLocked(revision uint64) {
	base := filepath.Join(s.history, revisionName(revision))
	_ = os.Remove(base + ".yaml")
	_ = os.Remove(base + ".json")
}

func (s *Store) writeRevisionLocked(meta RevisionMeta, raw []byte) error {
	if err := os.MkdirAll(s.history, 0o700); err != nil {
		return err
	}
	base := filepath.Join(s.history, revisionName(meta.Revision))
	if err := atomicReplace(base+".yaml", raw, 0o600); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		s.removeRevisionLocked(meta.Revision)
		return err
	}
	if err := atomicReplace(base+".json", data, 0o600); err != nil {
		s.removeRevisionLocked(meta.Revision)
		return err
	}
	return nil
}

func readMeta(path string) (RevisionMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RevisionMeta{}, err
	}
	var meta RevisionMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return RevisionMeta{}, err
	}
	return meta, nil
}

func revisionName(revision uint64) string { return "revision-" + fmt.Sprintf("%06d", revision) }

func randomID() string {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

func draftSummary(d Draft) DraftSummary {
	return DraftSummary{ID: d.ID, Revision: d.Revision, BaseRevision: d.BaseRevision, UpdatedAt: d.UpdatedAt, Validated: d.Validated, DiffRevision: d.DiffRevision}
}

func cloneDraft(d Draft) Draft {
	d.Raw = append([]byte(nil), d.Raw...)
	return d
}
