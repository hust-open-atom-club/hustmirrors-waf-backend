package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

type UsageStore struct {
	pool   *pgxpool.Pool
	closed bool
}

func NewUsageStore(ctx context.Context, dsn string) (*UsageStore, error) {
	pool, err := OpenPool(ctx, PoolConfig{DSN: dsn})
	if err != nil {
		return nil, err
	}
	return &UsageStore{pool: pool}, nil
}

func NewUsageStoreFromPool(pool *pgxpool.Pool) *UsageStore {
	return &UsageStore{pool: pool}
}

// Consume uses INSERT ... ON CONFLICT to atomically increment uses while
// ensuring it stays <= max_uses, avoiding the race in a separate
// SELECT-then-UPDATE.
func (s *UsageStore) Consume(ctx context.Context, in storage.ConsumeInput) (storage.ConsumeResult, error) {
	if s.isClosed() {
		return storage.ConsumeResult{}, storage.ErrClosed
	}
	if in.SkipConsume {
		rec, err := s.Get(ctx, in.ID)
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ConsumeResult{Allowed: true, Uses: 0, MaxUses: in.MaxUses, Reason: "ok_head_first"}, nil
		}
		if err != nil {
			return storage.ConsumeResult{}, err
		}
		allowed := rec.Uses < in.MaxUses
		reason := "ok_head"
		if !allowed {
			reason = "used_up_head"
		}
		return storage.ConsumeResult{Allowed: allowed, Uses: rec.Uses, MaxUses: in.MaxUses, Reason: reason}, nil
	}

	const q = `
		INSERT INTO pow_usage (
			id, mode, path, sign, token_hash,
			uses, max_uses, first_ip, last_ip, user_agent,
			expires_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $7, $8, $9, $10, $10)
		ON CONFLICT (id) DO UPDATE
		SET uses = pow_usage.uses + 1,
		    last_ip = EXCLUDED.last_ip,
		    user_agent = COALESCE(NULLIF(pow_usage.user_agent, ''), EXCLUDED.user_agent),
		    updated_at = EXCLUDED.updated_at
		WHERE pow_usage.uses < pow_usage.max_uses
		RETURNING uses, max_uses
	`
	now := in.NowUnix
	if now == 0 {
		now = time.Now().Unix()
	}

	var uses, maxUses int
	err := s.pool.QueryRow(ctx, q,
		in.ID, in.Mode, in.Path, in.Sign, in.TokenHash,
		in.MaxUses, in.IP, in.UserAgent,
		in.ExpiresAt, now,
	).Scan(&uses, &maxUses)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			rec, getErr := s.Get(ctx, in.ID)
			if getErr != nil {
				return storage.ConsumeResult{}, getErr
			}
			return storage.ConsumeResult{Allowed: false, Uses: rec.Uses, MaxUses: rec.MaxUses, Reason: "used_up"}, nil
		}
		return storage.ConsumeResult{}, fmt.Errorf("postgres: consume: %w", err)
	}
	return storage.ConsumeResult{Allowed: true, Uses: uses, MaxUses: maxUses, Reason: "ok"}, nil
}

func (s *UsageStore) Get(ctx context.Context, id string) (*storage.UsageRecord, error) {
	if s.isClosed() {
		return nil, storage.ErrClosed
	}
	const q = `
		SELECT id, mode, path, sign, token_hash,
		       uses, max_uses, first_ip, last_ip, user_agent,
		       expires_at, created_at, updated_at
		FROM pow_usage
		WHERE id = $1
	`
	var r storage.UsageRecord
	var firstIP, lastIP, ua *string
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&r.ID, &r.Mode, &r.Path, &r.Sign, &r.TokenHash,
		&r.Uses, &r.MaxUses, &firstIP, &lastIP, &ua,
		&r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return nil, fmt.Errorf("postgres: pg error %s: %w", pgErr.Code, err)
		}
		return nil, fmt.Errorf("postgres: get: %w", err)
	}
	if firstIP != nil {
		r.FirstIP = *firstIP
	}
	if lastIP != nil {
		r.LastIP = *lastIP
	}
	if ua != nil {
		r.UserAgent = *ua
	}
	return &r, nil
}

func (s *UsageStore) CleanupExpired(ctx context.Context, beforeUnix int64) (int, error) {
	if s.isClosed() {
		return 0, storage.ErrClosed
	}
	const q = `DELETE FROM pow_usage WHERE expires_at < $1`
	tag, err := s.pool.Exec(ctx, q, beforeUnix)
	if err != nil {
		return 0, fmt.Errorf("postgres: cleanup: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *UsageStore) Close() error {
	if s.isClosed() {
		return nil
	}
	s.closed = true
	return nil
}

func (s *UsageStore) isClosed() bool {
	return s.closed
}

var _ storage.UsageStore = (*UsageStore)(nil)
