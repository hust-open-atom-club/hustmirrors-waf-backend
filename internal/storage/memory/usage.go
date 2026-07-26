package memory

import (
	"context"
	"sync"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

type UsageStore struct {
	mu      sync.Mutex
	records map[string]*storage.UsageRecord
	closed  bool
}

func NewUsageStore() *UsageStore {
	return &UsageStore{records: make(map[string]*storage.UsageRecord)}
}

func (s *UsageStore) Consume(_ context.Context, in storage.ConsumeInput) (storage.ConsumeResult, error) {
	if s.isClosed() {
		return storage.ConsumeResult{}, storage.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[in.ID]
	now := in.NowUnix
	if now == 0 {
		now = time.Now().Unix()
	}

	if !ok {
		rec = &storage.UsageRecord{
			ID:        in.ID,
			Mode:      in.Mode,
			Path:      in.Path,
			Sign:      in.Sign,
			TokenHash: in.TokenHash,
			Uses:      0,
			MaxUses:   in.MaxUses,
			FirstIP:   in.IP,
			LastIP:    in.IP,
			UserAgent: in.UserAgent,
			ExpiresAt: in.ExpiresAt,
			CreatedAt: now,
			UpdatedAt: now,
		}
		s.records[in.ID] = rec
	}

	if rec.Uses >= in.MaxUses {
		return storage.ConsumeResult{
			Allowed: false,
			Uses:    rec.Uses,
			MaxUses: in.MaxUses,
			Reason:  "used_up",
		}, nil
	}

	if !in.SkipConsume {
		rec.Uses++
	}
	rec.LastIP = in.IP
	rec.UpdatedAt = now
	if rec.UserAgent == "" {
		rec.UserAgent = in.UserAgent
	}

	return storage.ConsumeResult{
		Allowed: true,
		Uses:    rec.Uses,
		MaxUses: in.MaxUses,
		Reason:  "ok",
	}, nil
}

func (s *UsageStore) Get(_ context.Context, id string) (*storage.UsageRecord, error) {
	if s.isClosed() {
		return nil, storage.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

func (s *UsageStore) CleanupExpired(_ context.Context, beforeUnix int64) (int, error) {
	if s.isClosed() {
		return 0, storage.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, rec := range s.records {
		if rec.ExpiresAt < beforeUnix {
			delete(s.records, id)
			removed++
		}
	}
	return removed, nil
}

// CountActive reports the number of records currently held. Used to feed
// the storage_active_signatures gauge.
func (s *UsageStore) CountActive(_ context.Context) (int64, error) {
	if s.isClosed() {
		return 0, storage.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.records)), nil
}

func (s *UsageStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.records = nil
	return nil
}

func (s *UsageStore) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

var _ storage.UsageStore = (*UsageStore)(nil)
var _ storage.ActiveCounter = (*UsageStore)(nil)
