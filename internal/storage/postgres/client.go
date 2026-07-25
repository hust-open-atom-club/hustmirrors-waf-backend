package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PoolConfig struct {
	DSN          string
	MaxOpenConns int32
	MaxIdleConns int32
	MaxLifetime  time.Duration
	MaxIdleTime  time.Duration
}

func OpenPool(ctx context.Context, cfg PoolConfig) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}
	if cfg.MaxOpenConns > 0 {
		pc.MaxConns = cfg.MaxOpenConns
	} else {
		pc.MaxConns = 20
	}
	if cfg.MaxIdleConns > 0 {
		pc.MinConns = cfg.MaxIdleConns
	}
	if cfg.MaxLifetime > 0 {
		pc.MaxConnLifetime = cfg.MaxLifetime
	} else {
		pc.MaxConnLifetime = time.Hour
	}
	if cfg.MaxIdleTime > 0 {
		pc.MaxConnIdleTime = cfg.MaxIdleTime
	} else {
		pc.MaxConnIdleTime = 15 * time.Minute
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return pool, nil
}
