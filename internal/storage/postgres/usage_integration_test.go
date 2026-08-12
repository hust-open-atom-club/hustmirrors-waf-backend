//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

var schemaSequence atomic.Uint64

func newIntegrationStore(t *testing.T) (*UsageStore, *pgxpool.Pool) {
	t.Helper()

	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	adminConfig, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	adminConfig.MaxConns = 4

	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	require.NoError(t, err)
	require.NoError(t, adminPool.Ping(ctx))

	schema := fmt.Sprintf("waf_test_%d_%d", os.Getpid(), schemaSequence.Add(1))
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	_, err = adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)

	var testPool *pgxpool.Pool
	t.Cleanup(func() {
		if testPool != nil {
			testPool.Close()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_, dropErr := adminPool.Exec(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		adminPool.Close()
		assert.NoError(t, dropErr)
	})

	testConfig, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	testConfig.MaxConns = 32
	testConfig.ConnConfig.RuntimeParams["search_path"] = schema

	testPool, err = pgxpool.NewWithConfig(ctx, testConfig)
	require.NoError(t, err)
	require.NoError(t, testPool.Ping(ctx))

	applyIntegrationMigration(t, ctx, testPool)
	return NewUsageStoreFromPool(testPool), testPool
}

func applyIntegrationMigration(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	migrationPath := filepath.Join(filepath.Dir(filename), "..", "..", "..", "migrations", "001_init.sql")
	raw, err := os.ReadFile(migrationPath)
	require.NoError(t, err)

	upSQL, _, found := strings.Cut(string(raw), "-- +goose Down")
	require.True(t, found, "migration must contain a goose Down section")
	_, err = pool.Exec(ctx, upSQL)
	require.NoError(t, err)
}

func integrationInput(id string, maxUses int, ip string, now int64) storage.ConsumeInput {
	return storage.ConsumeInput{
		ID:        id,
		Mode:      "generic",
		Path:      "/images/test.iso",
		Sign:      "deadbeef",
		TokenHash: "token-hash",
		ExpiresAt: now + 600,
		MaxUses:   maxUses,
		IP:        ip,
		UserAgent: "test-agent",
		NowUnix:   now,
	}
}

func TestUsageStoreIntegration_ConsumeAndGet(t *testing.T) {
	store, _ := newIntegrationStore(t)
	now := time.Now().Unix()

	first := integrationInput("consume-and-get", 3, "192.0.2.1", now)
	first.UserAgent = ""
	result, err := store.Consume(context.Background(), first)
	require.NoError(t, err)
	assert.Equal(t, storage.ConsumeResult{Allowed: true, Uses: 1, MaxUses: 3, Reason: "ok"}, result)

	second := first
	second.IP = "192.0.2.2"
	second.UserAgent = "second-agent"
	second.NowUnix = now + 10
	result, err = store.Consume(context.Background(), second)
	require.NoError(t, err)
	assert.Equal(t, storage.ConsumeResult{Allowed: true, Uses: 2, MaxUses: 3, Reason: "ok"}, result)

	record, err := store.Get(context.Background(), first.ID)
	require.NoError(t, err)
	assert.Equal(t, first.ID, record.ID)
	assert.Equal(t, first.Mode, record.Mode)
	assert.Equal(t, first.Path, record.Path)
	assert.Equal(t, first.Sign, record.Sign)
	assert.Equal(t, first.TokenHash, record.TokenHash)
	assert.Equal(t, 2, record.Uses)
	assert.Equal(t, 3, record.MaxUses)
	assert.Equal(t, first.IP, record.FirstIP)
	assert.Equal(t, second.IP, record.LastIP)
	assert.Equal(t, second.UserAgent, record.UserAgent)
	assert.Equal(t, first.ExpiresAt, record.ExpiresAt)
	assert.Equal(t, now, record.CreatedAt)
	assert.Equal(t, now+10, record.UpdatedAt)
}

func TestUsageStoreIntegration_UsedUp(t *testing.T) {
	store, _ := newIntegrationStore(t)
	now := time.Now().Unix()
	input := integrationInput("used-up", 2, "192.0.2.1", now)

	for wantUses := 1; wantUses <= input.MaxUses; wantUses++ {
		result, err := store.Consume(context.Background(), input)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
		assert.Equal(t, wantUses, result.Uses)
	}

	result, err := store.Consume(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, storage.ConsumeResult{Allowed: false, Uses: 2, MaxUses: 2, Reason: "used_up"}, result)
}

func TestUsageStoreIntegration_ConcurrentConsumeRespectsMaxUses(t *testing.T) {
	store, _ := newIntegrationStore(t)
	const workers = 24
	const maxUses = 5

	input := integrationInput("concurrent", maxUses, "192.0.2.1", time.Now().Unix())
	results := make(chan storage.ConsumeResult, workers)
	errorsCh := make(chan error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			result, err := store.Consume(context.Background(), input)
			if err != nil {
				errorsCh <- err
				return
			}
			results <- result
		}()
	}
	wg.Wait()
	close(results)
	close(errorsCh)

	for err := range errorsCh {
		assert.NoError(t, err)
	}
	allowed := 0
	for result := range results {
		if result.Allowed {
			allowed++
		}
	}
	assert.Equal(t, maxUses, allowed)

	record, err := store.Get(context.Background(), input.ID)
	require.NoError(t, err)
	assert.Equal(t, maxUses, record.Uses)
}

func TestUsageStoreIntegration_SkipConsume(t *testing.T) {
	store, _ := newIntegrationStore(t)
	now := time.Now().Unix()
	input := integrationInput("skip-consume", 1, "192.0.2.1", now)
	input.SkipConsume = true

	result, err := store.Consume(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, storage.ConsumeResult{Allowed: true, Uses: 0, MaxUses: 1, Reason: "ok_head_first"}, result)
	_, err = store.Get(context.Background(), input.ID)
	require.ErrorIs(t, err, storage.ErrNotFound)

	input.SkipConsume = false
	result, err = store.Consume(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 1, result.Uses)

	input.SkipConsume = true
	result, err = store.Consume(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, storage.ConsumeResult{Allowed: false, Uses: 1, MaxUses: 1, Reason: "used_up_head"}, result)

	record, err := store.Get(context.Background(), input.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, record.Uses)
}

func TestUsageStoreIntegration_GetNotFound(t *testing.T) {
	store, _ := newIntegrationStore(t)
	_, err := store.Get(context.Background(), "missing")
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestUsageStoreIntegration_CleanupExpiredAndCountActive(t *testing.T) {
	store, _ := newIntegrationStore(t)
	now := time.Now().Unix()

	expired := integrationInput("expired", 2, "192.0.2.1", now)
	expired.ExpiresAt = now - 1
	boundary := integrationInput("boundary", 2, "192.0.2.1", now)
	boundary.ExpiresAt = now
	active := integrationInput("active", 2, "192.0.2.1", now)
	active.ExpiresAt = now + 600

	for _, input := range []storage.ConsumeInput{expired, boundary, active} {
		_, err := store.Consume(context.Background(), input)
		require.NoError(t, err)
	}

	activeCount, err := store.CountActive(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, activeCount, int64(1))

	removed, err := store.CleanupExpired(context.Background(), now)
	require.NoError(t, err)
	assert.Equal(t, 1, removed, "expires_at equal to the boundary must be preserved")

	_, err = store.Get(context.Background(), expired.ID)
	require.ErrorIs(t, err, storage.ErrNotFound)
	_, err = store.Get(context.Background(), boundary.ID)
	require.NoError(t, err)
	_, err = store.Get(context.Background(), active.ID)
	require.NoError(t, err)
}

func TestUsageStoreIntegration_CloseDoesNotCloseBorrowedPool(t *testing.T) {
	store, pool := newIntegrationStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())

	input := integrationInput("closed", 1, "192.0.2.1", time.Now().Unix())
	_, err := store.Consume(context.Background(), input)
	require.ErrorIs(t, err, storage.ErrClosed)
	_, err = store.Get(context.Background(), input.ID)
	require.ErrorIs(t, err, storage.ErrClosed)
	_, err = store.CleanupExpired(context.Background(), time.Now().Unix())
	require.ErrorIs(t, err, storage.ErrClosed)
	_, err = store.CountActive(context.Background())
	require.ErrorIs(t, err, storage.ErrClosed)

	var one int
	err = pool.QueryRow(context.Background(), "SELECT 1").Scan(&one)
	require.NoError(t, err)
	assert.Equal(t, 1, one)
}

func TestUsageStoreIntegration_CloseDuringReads(t *testing.T) {
	store, _ := newIntegrationStore(t)
	input := integrationInput("close-during-reads", 100, "192.0.2.1", time.Now().Unix())
	_, err := store.Consume(context.Background(), input)
	require.NoError(t, err)

	start := make(chan struct{})
	done := make(chan error, 16)
	for range cap(done) {
		go func() {
			<-start
			_, getErr := store.Get(context.Background(), input.ID)
			if getErr != nil && !errors.Is(getErr, storage.ErrClosed) {
				done <- getErr
				return
			}
			done <- nil
		}()
	}
	close(start)
	require.NoError(t, store.Close())

	for range cap(done) {
		assert.NoError(t, <-done)
	}
}
