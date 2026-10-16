package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestUnmanagedStoreDoesNotTouchFilesystem(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "missing", "nested", "config.yaml")
	store, err := New(path, []byte("initial"), false)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "missing")); !os.IsNotExist(err) {
		t.Fatalf("unmanaged New() touched filesystem: Stat error = %v", err)
	}

	tests := []struct {
		name string
		run  func() error
	}{
		{name: "save draft", run: func() error {
			_, err := store.SaveDraft(0, "", 0, []byte("draft"))
			return err
		}},
		{name: "discard draft", run: func() error { return store.DiscardDraft("draft", 0) }},
		{name: "apply", run: func() error {
			_, err := store.Apply(ApplyRequest{Raw: []byte("next")})
			return err
		}},
		{name: "history", run: func() error {
			_, err := store.History(10)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, ErrUnmanaged) {
				t.Fatalf("error = %v, want ErrUnmanaged", err)
			}
			if _, err := os.Stat(filepath.Join(root, "missing")); !os.IsNotExist(err) {
				t.Fatalf("operation touched filesystem: Stat error = %v", err)
			}
		})
	}
}

func TestManagedStoreBootstrapsRevision(t *testing.T) {
	store, path, initial := newManagedStore(t)

	status := store.Status()
	if !status.Managed || status.CurrentRevision != 1 || status.CurrentUpdatedAt.IsZero() {
		t.Fatalf("Status() = %+v, want managed bootstrap revision 1", status)
	}

	revision, err := store.HistoryGet(1)
	if err != nil {
		t.Fatalf("HistoryGet(1) error = %v", err)
	}
	if revision.Meta.Revision != 1 || revision.Meta.Action != "bootstrap" || revision.Meta.ParentRevision != 0 {
		t.Fatalf("bootstrap metadata = %+v", revision.Meta)
	}
	if string(revision.Raw) != string(initial) {
		t.Fatalf("bootstrap raw = %q, want %q", revision.Raw, initial)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), historyDirName, "revision-000001.json")); err != nil {
		t.Fatalf("bootstrap metadata file missing: %v", err)
	}
}

func TestDraftCASAndExpiry(t *testing.T) {
	store, _, _ := newManagedStore(t)
	baseTime := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return baseTime }

	draft, err := store.SaveDraft(1, "", 0, []byte("draft-1"))
	if err != nil {
		t.Fatalf("SaveDraft(create) error = %v", err)
	}
	if draft.ID == "" || draft.Revision != 1 || draft.BaseRevision != 1 || !draft.UpdatedAt.Equal(baseTime) {
		t.Fatalf("created draft = %+v", draft)
	}

	tests := []struct {
		name             string
		id               string
		expectedRevision uint64
		wantErr          error
	}{
		{name: "missing id", id: "", expectedRevision: 1, wantErr: ErrDraftConflict},
		{name: "wrong id", id: "other", expectedRevision: 1, wantErr: ErrDraftConflict},
		{name: "stale revision", id: draft.ID, expectedRevision: 0, wantErr: ErrDraftConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, saveErr := store.SaveDraft(1, tt.id, tt.expectedRevision, []byte("rejected"))
			if !errors.Is(saveErr, tt.wantErr) {
				t.Fatalf("SaveDraft() error = %v, want %v", saveErr, tt.wantErr)
			}
		})
	}

	baseTime = baseTime.Add(time.Hour)
	updated, err := store.SaveDraft(1, draft.ID, draft.Revision, []byte("draft-2"))
	if err != nil {
		t.Fatalf("SaveDraft(update) error = %v", err)
	}
	if updated.Revision != 2 || string(updated.Raw) != "draft-2" || !updated.UpdatedAt.Equal(baseTime) {
		t.Fatalf("updated draft = %+v", updated)
	}

	baseTime = baseTime.Add(24*time.Hour + time.Nanosecond)
	if _, err := store.GetDraft(draft.ID); !errors.Is(err, ErrDraftExpired) {
		t.Fatalf("GetDraft(expired) error = %v, want ErrDraftExpired", err)
	}
	if store.Status().Draft != nil {
		t.Fatal("expired draft remains visible in status")
	}
}

func TestApplyAtomicallyReplacesCurrentAndRecordsHistory(t *testing.T) {
	store, path, _ := newManagedStore(t)
	appliedAt := time.Date(2026, time.August, 13, 13, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return appliedAt }
	if _, err := store.SaveDraft(1, "", 0, []byte("draft")); err != nil {
		t.Fatalf("SaveDraft() error = %v", err)
	}

	result, err := store.Apply(ApplyRequest{
		Raw:              []byte("version: 2\n"),
		ExpectedRevision: 1,
		Actor:            "operator",
		Reason:           "routine update",
		Changed:          3,
		Danger:           "low",
		RestartRequired:  true,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Revision != 2 || result.Previous != 1 || result.Meta.Action != "apply" {
		t.Fatalf("Apply() result = %+v", result)
	}
	if got, readErr := os.ReadFile(path); readErr != nil || string(got) != "version: 2\n" {
		t.Fatalf("active file = %q, error = %v", got, readErr)
	}
	status := store.Status()
	if status.CurrentRevision != 2 || !status.CurrentUpdatedAt.Equal(appliedAt) || !status.PendingRestart || status.Draft != nil {
		t.Fatalf("Status() after apply = %+v", status)
	}

	history, err := store.History(10)
	if err != nil {
		t.Fatalf("History() error = %v", err)
	}
	if len(history) != 2 || history[0].Revision != 2 || history[1].Revision != 1 {
		t.Fatalf("History() = %+v, want revisions 2 then 1", history)
	}
	revision, err := store.HistoryGet(2)
	if err != nil {
		t.Fatalf("HistoryGet(2) error = %v", err)
	}
	if string(revision.Raw) != "version: 2\n" || revision.Meta.ParentRevision != 1 || revision.Meta.Actor != "operator" || revision.Meta.Reason != "routine update" || revision.Meta.Changed != 3 || revision.Meta.Danger != "low" || !revision.Meta.RestartRequired || !revision.Meta.CreatedAt.Equal(appliedAt) {
		t.Fatalf("revision 2 = %+v, raw = %q", revision.Meta, revision.Raw)
	}
}

func TestApplyRejectsExternalEditWithoutOverwrite(t *testing.T) {
	store, path, initial := newManagedStore(t)
	external := []byte("externally: edited\n")
	if err := os.WriteFile(path, external, 0o600); err != nil {
		t.Fatalf("external edit: %v", err)
	}

	_, err := store.Apply(ApplyRequest{Raw: []byte("candidate: value\n"), ExpectedRevision: 1})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Apply() error = %v, want ErrConflict", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(active) error = %v", err)
	}
	if string(got) != string(external) {
		t.Fatalf("active file = %q, want external edit %q", got, external)
	}
	revision, raw, err := store.Current()
	if err != nil || revision != 1 || string(raw) != string(initial) {
		t.Fatalf("Current() = (%d, %q, %v), want bootstrap state", revision, raw, err)
	}
	assertNoRevision(t, store, 2)
}

func TestRollbackStyleApplyPreservesMetadata(t *testing.T) {
	store, _, _ := newManagedStore(t)
	result, err := store.Apply(ApplyRequest{
		Raw:              []byte("restored: true\n"),
		ExpectedRevision: 1,
		Action:           "rollback",
		RollbackTarget:   1,
		Actor:            "admin@example.com",
		Reason:           "restore known good configuration",
		Changed:          7,
		Danger:           "high",
		RestartRequired:  true,
	})
	if err != nil {
		t.Fatalf("Apply(rollback) error = %v", err)
	}
	meta := result.Meta
	if meta.Action != "rollback" || meta.RollbackTarget != 1 || meta.ParentRevision != 1 || meta.Actor != "admin@example.com" || meta.Reason != "restore known good configuration" || meta.Changed != 7 || meta.Danger != "high" || !meta.RestartRequired {
		t.Fatalf("rollback metadata = %+v", meta)
	}
	stored, err := store.HistoryGet(result.Revision)
	if err != nil {
		t.Fatalf("HistoryGet(%d) error = %v", result.Revision, err)
	}
	if !stored.Meta.CreatedAt.Equal(meta.CreatedAt) {
		t.Fatalf("stored CreatedAt = %v, want %v", stored.Meta.CreatedAt, meta.CreatedAt)
	}
	storedMeta, wantMeta := stored.Meta, meta
	storedMeta.CreatedAt, wantMeta.CreatedAt = time.Time{}, time.Time{}
	if storedMeta != wantMeta {
		t.Fatalf("stored metadata = %+v, want %+v", stored.Meta, meta)
	}
}

func TestFailedApplyDoesNotPublishPhantomRevision(t *testing.T) {
	store, _, _ := newManagedStore(t)
	failurePath := applyFailurePath(t)
	existing, err := os.ReadFile(failurePath)
	if err != nil {
		t.Fatalf("read failure target %q: %v", failurePath, err)
	}
	store.path = failurePath
	store.raw = append([]byte(nil), existing...)

	if _, applyErr := store.Apply(ApplyRequest{Raw: []byte("must not publish"), ExpectedRevision: 1}); applyErr == nil {
		t.Fatal("Apply() error = nil, want replacement failure")
	}
	revision, raw, err := store.Current()
	if err != nil || revision != 1 || string(raw) != string(existing) {
		t.Fatalf("Current() = (%d, %q, %v), want unchanged revision 1", revision, raw, err)
	}
	if store.Status().CurrentRevision != 1 {
		t.Fatalf("Status().CurrentRevision = %d, want 1", store.Status().CurrentRevision)
	}
	assertNoRevision(t, store, 2)
}

func newManagedStore(t *testing.T) (*Store, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	initial := []byte("version: 1\n")
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatalf("write initial config: %v", err)
	}
	store, err := New(path, initial, true)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return store, path, initial
}

func assertNoRevision(t *testing.T, store *Store, revision uint64) {
	t.Helper()
	if _, err := store.HistoryGet(revision); !errors.Is(err, ErrRevisionNotFound) {
		t.Fatalf("HistoryGet(%d) error = %v, want ErrRevisionNotFound", revision, err)
	}
	history, err := store.History(10)
	if err != nil {
		t.Fatalf("History() error = %v", err)
	}
	for _, meta := range history {
		if meta.Revision == revision {
			t.Fatalf("phantom revision %d found in history", revision)
		}
	}
}

func applyFailurePath(t *testing.T) string {
	t.Helper()
	switch runtime.GOOS {
	case "windows":
		return "NUL"
	case "linux":
		return "/proc/self/status"
	default:
		t.Skip("no deterministic readable-but-not-replaceable path for this platform")
		return ""
	}
}
