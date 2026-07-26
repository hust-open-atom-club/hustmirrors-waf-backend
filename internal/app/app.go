package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/admin"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/auth"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/clock"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/matcher"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/metrics"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
	pgstore "github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/postgres"
	memstore "github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
	redisstore "github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/redis"
	echo "github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/transport/echo"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version"
)

type App struct {
	cfg      *config.Config
	logger   logging.Logger
	metrics  *metrics.Container
	authSvc  *auth.Service
	adminSvc *admin.Service
	mainSrv  *echo.Server
	adminSrv *echo.Server

	storageCloser func() error
	redisClient   *redis.Client
	cleanupStop   context.CancelFunc
	cleanupWG     sync.WaitGroup
}

func Build(ctx context.Context, cfg *config.Config) (*App, error) {
	if cfg == nil {
		return nil, errors.New("app: config is nil")
	}

	logger, err := logging.New(cfg.Logging.Level, cfg.Logging.Format)
	if err != nil {
		return nil, fmt.Errorf("app: init logging: %w", err)
	}
	logger.Info(ctx, "starting mirrors-waf-backend",
		logging.String("version", version.Get().Version),
		logging.String("commit", version.Get().Commit),
	)
	logger.Info(ctx, "config loaded",
		logging.String("listen", cfg.Server.Listen),
		logging.String("storage_driver", cfg.Storage.Driver),
		logging.String("counter_driver", cfg.Storage.CounterDriver),
		logging.Bool("risk_control", cfg.RiskControl.Enabled),
		logging.Bool("admin_enabled", cfg.Admin.Enabled),
	)

	m := metrics.New()
	if err := m.Register(); err != nil {
		logger.Warn(ctx, "metrics register failed (continuing)", logging.Err(err))
	}

	clk := clock.New()

	protected, err := buildProtectedMatcher(cfg)
	if err != nil {
		return nil, err
	}
	excluded, err := buildExcludedMatcher(cfg)
	if err != nil {
		return nil, err
	}
	matcherComposite := matcher.NewComposite(protected, excluded)

	usageStore, counterStore, redisClient, storageCloser, err := buildStorage(ctx, cfg, m, logger)
	if err != nil {
		return nil, err
	}

	var riskEngine *risk.Engine
	var counterReg *risk.CounterRegistry
	if cfg.RiskControl.Enabled {
		riskEngine, err = risk.FromConfig(cfg.RiskControl)
		if err != nil {
			storageCloser()
			return nil, fmt.Errorf("app: build risk engine: %w", err)
		}
		if counterStore != nil {
			counterReg = risk.NewCounterRegistry(cfg.RiskControl.Counters, counterStore)
		} else {
			logger.Warn(ctx, "risk_control enabled but no counter store available; counter rules will not fire")
			counterReg = risk.NewCounterRegistry(cfg.RiskControl.Counters, nil)
		}
	}

	authSvc, err := auth.New(auth.Options{
		Config:     cfg,
		Matcher:    matcherComposite,
		UsageStore: usageStore,
		Clock:      clk,
		Logger:     logger,
		Metrics:    m,
		RiskEngine: riskEngine,
		CounterReg: counterReg,
	})
	if err != nil {
		storageCloser()
		return nil, fmt.Errorf("app: build auth service: %w", err)
	}

	var adminSvc *admin.Service
	if cfg.Admin.Enabled {
		if cfg.Admin.Auth.TokenFile != "" {
			b, err := os.ReadFile(cfg.Admin.Auth.TokenFile)
			if err != nil {
				storageCloser()
				return nil, fmt.Errorf("app: read admin token file: %w", err)
			}
			cfg.Admin.Auth.Token = strings.TrimSpace(string(b))
		}
		adminSvc, err = admin.New(admin.Options{
			Config:    cfg,
			AuditLog:  admin.NopAuditLogger{},
			Validator: admin.DefaultValidator{},
			RiskEngine: riskEngine,
		})
		if err != nil {
			storageCloser()
			return nil, fmt.Errorf("app: build admin service: %w", err)
		}
	}

	a := &App{
		cfg:           cfg,
		logger:        logger,
		metrics:       m,
		authSvc:       authSvc,
		adminSvc:      adminSvc,
		storageCloser: storageCloser,
		redisClient:   redisClient,
	}

	a.mainSrv = echo.NewMain(echo.MainOptions{
		Config:  cfg,
		Logger:  logger,
		Metrics: m,
		AuthSvc: authSvc,
	})

	if adminSvc != nil {
		a.adminSrv = echo.NewAdmin(echo.AdminOptions{
			Config:   cfg,
			Logger:   logger,
			Metrics:  m,
			AdminSvc: adminSvc,
		})
	}

	if cfg.Cleanup.Enabled && usageStore != nil {
		cleanupCtx, cancel := context.WithCancel(context.Background())
		a.cleanupStop = cancel
		a.cleanupWG.Add(1)
		go a.cleanupLoop(cleanupCtx, usageStore)
	}

	return a, nil
}

func (a *App) Start() error {
	errs := make(chan error, 2)

	go func() {
		a.logger.Info(context.Background(), "main server listening", logging.String("addr", a.cfg.Server.Listen))
		if err := a.mainSrv.Start(a.cfg.Server.Listen); err != nil {
			errs <- err
		}
	}()

	if a.adminSrv != nil {
		go func() {
			a.logger.Info(context.Background(), "admin server listening", logging.String("addr", a.cfg.Admin.Listen))
			if err := a.adminSrv.Start(a.cfg.Admin.Listen); err != nil {
				errs <- err
			}
		}()
	}

	return <-errs
}

func (a *App) Shutdown(ctx context.Context) error {
	a.logger.Info(ctx, "shutting down")

	// Stop cleanup loop first so it doesn't race with storage close.
	if a.cleanupStop != nil {
		a.cleanupStop()
		a.cleanupWG.Wait()
	}

	var errs []error
	shutdownCtx, cancel := context.WithTimeout(ctx, a.cfg.Server.ShutdownTimeout)
	defer cancel()

	if a.mainSrv != nil {
		if err := a.mainSrv.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("main server shutdown: %w", err))
		}
	}
	if a.adminSrv != nil {
		if err := a.adminSrv.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("admin server shutdown: %w", err))
		}
	}
	if a.storageCloser != nil {
		if err := a.storageCloser(); err != nil {
			errs = append(errs, fmt.Errorf("storage close: %w", err))
		}
	}
	if a.redisClient != nil {
		_ = a.redisClient.Close()
	}

	if a.logger != nil {
		a.logger.Info(ctx, "shutdown complete")
		_ = a.logger.Sync()
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

func WaitForSignal() os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	return <-ch
}

func (a *App) cleanupLoop(ctx context.Context, store storage.UsageStore) {
	defer a.cleanupWG.Done()
	ticker := time.NewTicker(a.cfg.Cleanup.Interval)
	defer ticker.Stop()
	a.refreshActiveGauge(ctx, store)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			threshold := now.Add(-a.cfg.Cleanup.ExpiredGracePeriod).Unix()
			removed, err := store.CleanupExpired(ctx, threshold)
			if err != nil {
				a.logger.Warn(ctx, "cleanup expired failed", logging.Err(err))
				continue
			}
			if removed > 0 {
				a.logger.Info(ctx, "cleanup expired records",
					logging.Int("removed", removed),
					logging.Int64("threshold", threshold),
				)
			}
			a.refreshActiveGauge(ctx, store)
		}
	}
}

// refreshActiveGauge updates the active_signatures gauge when the store
// supports counting. Drivers that don't implement ActiveCounter (redis)
// simply leave the gauge untouched.
func (a *App) refreshActiveGauge(ctx context.Context, store storage.UsageStore) {
	if a.metrics == nil {
		return
	}
	counter, ok := store.(storage.ActiveCounter)
	if !ok {
		return
	}
	n, err := counter.CountActive(ctx)
	if err != nil {
		if !errors.Is(err, storage.ErrUnsupported) {
			a.logger.Warn(ctx, "count active signatures failed", logging.Err(err))
		}
		return
	}
	a.metrics.ActiveSignatures.Set(float64(n))
}

// buildProtectedMatcher builds the "should this path require PoW" matcher.
//
// A regex that fails to compile is fatal rather than skipped: silently
// degrading to extension-only matching would leave every regex-protected
// path unguarded, which is exactly the failure an operator would not
// notice. Config validation rejects bad patterns first, so reaching the
// error path means validation and this function have drifted apart.
func buildProtectedMatcher(cfg *config.Config) (matcher.Matcher, error) {
	ext := matcher.NewExtensionMatcher(cfg.Protection.ProtectedExtensions)
	if len(cfg.Protection.ProtectedPaths) == 0 {
		return ext, nil
	}
	regex, err := matcher.NewRegexMatcher(cfg.Protection.ProtectedPaths)
	if err != nil {
		return nil, fmt.Errorf("app: compile protection.protected_paths: %w", err)
	}
	return unionMatcher{a: ext, b: regex}, nil
}

// buildExcludedMatcher builds the exclusion matcher. As above, a bad
// pattern is fatal: returning nil would drop the exclusion list entirely
// and subject paths meant to be exempt to PoW.
func buildExcludedMatcher(cfg *config.Config) (matcher.Matcher, error) {
	if len(cfg.Protection.ExcludedPaths) == 0 {
		return nil, nil
	}
	regex, err := matcher.NewRegexMatcher(cfg.Protection.ExcludedPaths)
	if err != nil {
		return nil, fmt.Errorf("app: compile protection.excluded_paths: %w", err)
	}
	return regex, nil
}

type unionMatcher struct{ a, b matcher.Matcher }

func (u unionMatcher) ShouldProtect(p string) bool {
	return u.a.ShouldProtect(p) || u.b.ShouldProtect(p)
}

func buildStorage(ctx context.Context, cfg *config.Config, m *metrics.Container, logger logging.Logger) (storage.UsageStore, storage.CounterStore, *redis.Client, func() error, error) {
	var (
		usageStore   storage.UsageStore
		counterStore storage.CounterStore
		redisClient  *redis.Client
		pgPool       *pgxpool.Pool
	)

	// The Redis client is shared by the usage store and the counter store,
	// so it is opened once up front if either driver asks for it.
	needRedis := cfg.Storage.Driver == "redis" || cfg.Storage.CounterDriver == "redis"
	if needRedis {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Storage.Redis.Addr,
			Password: cfg.Storage.Redis.Password,
			DB:       cfg.Storage.Redis.DB,
		})
		if err := redisClient.Ping(ctx).Err(); err != nil {
			_ = redisClient.Close()
			redisClient = nil
			// Counters are advisory - degrading them to in-memory only costs
			// accuracy across restarts. Usage records are authoritative: the
			// max_uses cap is the entire point of generic mode, so silently
			// falling back would let every token be replayed indefinitely.
			if cfg.Storage.Driver == "redis" {
				return nil, nil, nil, nil, fmt.Errorf("app: connect redis for usage store: %w", err)
			}
			logger.Warn(ctx, "redis ping failed; falling back to memory counter store", logging.Err(err))
		}
	}

	switch cfg.Storage.Driver {
	case "memory":
		usageStore = storage.InstrumentUsage("memory", m, memstore.NewUsageStore())
	case "postgres":
		pool, err := pgstore.OpenPool(ctx, pgstore.PoolConfig{
			DSN:          cfg.Storage.Postgres.DSN,
			MaxOpenConns: int32(cfg.Storage.Postgres.MaxOpenConns),
			MaxIdleConns: int32(cfg.Storage.Postgres.MaxIdleConns),
		})
		if err != nil {
			if redisClient != nil {
				_ = redisClient.Close()
			}
			return nil, nil, nil, nil, fmt.Errorf("app: open postgres pool: %w", err)
		}
		pgPool = pool
		usageStore = storage.InstrumentUsage("postgres", m, pgstore.NewUsageStoreFromPool(pool))
	case "redis":
		usageStore = storage.InstrumentUsage("redis", m,
			redisstore.NewUsageStore(redisClient, cfg.Storage.Redis.KeyPrefix))
	}

	switch cfg.Storage.CounterDriver {
	case "memory":
		counterStore = storage.InstrumentCounter("memory", m, memstore.NewCounterStore())
	case "redis":
		if redisClient != nil {
			counterStore = storage.InstrumentCounter("redis", m,
				redisstore.NewCounterStore(redisClient, cfg.Storage.Redis.KeyPrefix))
		} else {
			counterStore = storage.InstrumentCounter("memory", m, memstore.NewCounterStore())
		}
	}

	closer := func() error {
		var errs []error
		if usageStore != nil {
			if err := usageStore.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if counterStore != nil {
			if err := counterStore.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if pgPool != nil {
			pgPool.Close()
		}
		if len(errs) > 0 {
			return fmt.Errorf("storage close errors: %v", errs)
		}
		return nil
	}
	return usageStore, counterStore, redisClient, closer, nil
}
