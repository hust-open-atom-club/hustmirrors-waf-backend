//go:build benchmark

// Package benchmark provides load tests for mirrors-waf-backend.
//
// Run with:
//
//	go test -tags=benchmark -bench=. -benchmem ./internal/app/...
//
// The build tag keeps these tests out of the normal `go test` run.
package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
)

// BenchmarkVerifyPow_NotProtected measures the fast path: a request to a
// non-protected file. No PoW, no storage — just matcher + log.
func BenchmarkVerifyPow_NotProtected(b *testing.B) {
	a := buildBenchApp(b)
	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Original-URI", "/index.html")
	req.Header.Set("X-Real-IP", "10.0.0.1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		a.mainSrv.Echo().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rec.Code)
		}
	}
}

// BenchmarkVerifyPow_ProtectedNoToken measures the rate-limit path: a
// protected file without token. Goes through risk engine.
func BenchmarkVerifyPow_ProtectedNoToken(b *testing.B) {
	a := buildBenchApp(b)
	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Original-URI", "/ubuntu.iso")
	req.Header.Set("X-Real-IP", "10.0.0.2")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		a.mainSrv.Echo().ServeHTTP(rec, req)
	}
}

// BenchmarkVerifyPow_MalformedToken measures the deny path: a protected
// file with a malformed token. Goes through DecodeToken + ValidatePayload
// before failing.
func BenchmarkVerifyPow_MalformedToken(b *testing.B) {
	a := buildBenchApp(b)
	req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
	req.Header.Set("X-Original-URI", "/ubuntu.iso")
	req.Header.Set("X-Original-Args", "token=invalid&sign=0000000000000000000000000000000000000000000000000000000000000000")
	req.Header.Set("X-Real-IP", "10.0.0.3")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		a.mainSrv.Echo().ServeHTTP(rec, req)
	}
}

// BenchmarkVerifyPow_Concurrent measures throughput under concurrency.
// Uses b.RunParallel to spawn GOMAXPROCS workers.
func BenchmarkVerifyPow_Concurrent(b *testing.B) {
	a := buildBenchApp(b)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest(http.MethodGet, "/verify_pow", nil)
		req.Header.Set("X-Original-URI", "/ubuntu.iso")
		req.Header.Set("X-Real-IP", "10.0.0.4")
		rec := httptest.NewRecorder()
		for pb.Next() {
			a.mainSrv.Echo().ServeHTTP(rec, req)
		}
	})
}

func buildBenchApp(b *testing.B) *App {
	b.Helper()
	// Minimal config: memory storage, risk control off, low difficulty.
	cfg := &config.Config{}
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.ReadTimeout = 2 * time.Second
	cfg.Server.WriteTimeout = 2 * time.Second
	cfg.Pow.TokenParam = "token"
	cfg.Pow.SignParam = "sign"
	cfg.Pow.Algorithm = "sha256"
	cfg.Pow.PublicSalt = "bench-salt"
	cfg.Pow.AllowEmptySalt = true
	cfg.Pow.Modes.IPBound.Enabled = true
	cfg.Pow.Modes.IPBound.MinDifficulty = 1
	cfg.Pow.Modes.IPBound.MaxDifficulty = 32
	cfg.Pow.Modes.IPBound.MaxTTLSeconds = 86400
	cfg.Pow.Modes.Generic.Enabled = true
	cfg.Pow.Modes.Generic.MinDifficulty = 1
	cfg.Pow.Modes.Generic.MaxDifficulty = 32
	cfg.Pow.Modes.Generic.MaxTTLSeconds = 1800
	cfg.Pow.Modes.Generic.MaxUses = 5
	cfg.Protection.ProtectedExtensions = []string{".iso"}
	cfg.Storage.Driver = "memory"
	cfg.Storage.CounterDriver = "memory"
	cfg.RiskControl.Enabled = false
	cfg.Admin.Enabled = false
	cfg.Logging.Level = "error"
	cfg.Logging.Format = "json"
	cfg.Cleanup.Enabled = false

	a, err := Build(context.Background(), cfg)
	if err != nil {
		b.Fatalf("Build failed: %v", err)
	}
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	return a
}
