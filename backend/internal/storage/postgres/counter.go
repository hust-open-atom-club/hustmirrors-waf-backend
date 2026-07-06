package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

type CounterStore struct {
	pool   *pgxpool.Pool
	closed bool
}

func NewCounterStore(pool *pgxpool.Pool) *CounterStore {
	return &CounterStore{pool: pool}
}

func (s *CounterStore) Incr(ctx context.Context, name, key string, window time.Duration) (int64, time.Duration, error) {
	if s.isClosed() {
		return 0, 0, storage.ErrClosed
	}
	if window <= 0 {
		return 0, 0, errInvalidWindow
	}
	now := time.Now()
	bucketStart := now.UnixNano() / int64(window) * int64(window)
	bucketExpires := time.Unix(0, bucketStart).Add(window)
	remaining := time.Until(bucketExpires)
	if remaining < 0 {
		remaining = 0
	}

	const q = `
		INSERT INTO risk_counter (name, key, bucket_start, value)
		VALUES ($1, $2, $3, 1)
		ON CONFLICT (name, key, bucket_start)
		DO UPDATE SET value = risk_counter.value + 1
		RETURNING value
	`
	var v int64
	err := s.pool.QueryRow(ctx, q, name, key, bucketStart).Scan(&v)
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: counter incr: %w", err)
	}
	return v, remaining, nil
}

func (s *CounterStore) Get(ctx context.Context, name, key string, window time.Duration) (int64, error) {
	if s.isClosed() {
		return 0, storage.ErrClosed
	}
	if window <= 0 {
		return 0, errInvalidWindow
	}
	now := time.Now()
	bucketStart := now.UnixNano() / int64(window) * int64(window)
	const q = `SELECT value FROM risk_counter WHERE name=$1 AND key=$2 AND bucket_start=$3`
	var v int64
	err := s.pool.QueryRow(ctx, q, name, key, bucketStart).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("postgres: counter get: %w", err)
	}
	return v, nil
}

func (s *CounterStore) Reset(ctx context.Context, name, key string, window time.Duration) error {
	if s.isClosed() {
		return storage.ErrClosed
	}
	if window <= 0 {
		return errInvalidWindow
	}
	now := time.Now()
	bucketStart := now.UnixNano() / int64(window) * int64(window)
	const q = `DELETE FROM risk_counter WHERE name=$1 AND key=$2 AND bucket_start=$3`
	_, err := s.pool.Exec(ctx, q, name, key, bucketStart)
	if err != nil {
		return fmt.Errorf("postgres: counter reset: %w", err)
	}
	return nil
}

// Close does not close the pool; it is typically shared with UsageStore and
// owned by the app layer.
func (s *CounterStore) Close() error {
	s.closed = true
	return nil
}

func (s *CounterStore) isClosed() bool { return s.closed }

var errInvalidWindow = errors.New("postgres: invalid counter window")
