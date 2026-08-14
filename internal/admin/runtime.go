package admin

import (
	"context"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/configstore"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

// UsageReader is the read-only storage capability exposed to the admin API.
type UsageReader interface {
	Get(ctx context.Context, id string) (*storage.UsageRecord, error)
}

// PendingSnapshotSource exposes the current instance's pending buckets.
type PendingSnapshotSource interface {
	Snapshot() []risk.PendingSnapshot
}

// IPBlockAdmin is the instance-scoped mutation capability used by Phase 2.
type IPBlockAdmin interface {
	Block(ip string, input risk.BlockInput) (risk.BlockResult, error)
	Unblock(ip string) (risk.BlockResult, error)
}

// ConfigState exposes the single-instance configuration history and draft store.
type ConfigState interface {
	Status() configstore.Status
	Current() (uint64, []byte, error)
	SaveDraft(baseRevision uint64, id string, expectedRevision uint64, raw []byte) (configstore.Draft, error)
	GetDraft(id string) (configstore.Draft, error)
	MarkDraftValidated(id string, revision, diffRevision uint64) error
	DiscardDraft(id string, expectedRevision uint64) error
	Apply(req configstore.ApplyRequest) (configstore.ApplyResult, error)
	History(limit int) ([]configstore.RevisionMeta, error)
	HistoryGet(revision uint64) (configstore.Revision, error)
}

// ComponentProbe is one runtime dependency health check.
type ComponentProbe struct {
	Name     string
	OKStatus string
	Detail   string
	Check    func(context.Context) error
}

func hasProbe(probes []ComponentProbe, name string) bool {
	for _, probe := range probes {
		if probe.Name == name {
			return true
		}
	}
	return false
}

func (p ComponentProbe) run(ctx context.Context) SourceStatus {
	status := p.OKStatus
	if status == "" {
		status = "ok"
	}
	result := SourceStatus{Name: p.Name, Status: status, Detail: p.Detail}
	if p.Check != nil {
		if err := p.Check(ctx); err != nil {
			result.Status = "error"
			result.Detail = err.Error()
		}
	}
	return result
}
