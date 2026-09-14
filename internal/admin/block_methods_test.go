package admin

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/risk"
)

func blockAdminService(t *testing.T, token string) (*Service, *risk.IPPendingBlocker) {
	t.Helper()
	cfg := &config.Config{}
	config.ApplyDefaults(cfg)
	cfg.Admin.Enabled = true
	cfg.Admin.Auth.Token = token
	cfg.Admin.MutationsEnabled = true
	cfg.Admin.IPBlock.Enabled = true
	cfg.Admin.IPBlock.DefaultTTL = time.Hour
	cfg.Admin.IPBlock.MaxTTL = 24 * time.Hour
	blocker := risk.NewIPPendingBlocker(4, time.Hour)
	t.Cleanup(func() { _ = blocker.Close() })
	svc, err := New(Options{Config: cfg, Pending: blocker, IPBlocks: blocker})
	require.NoError(t, err)
	return svc, blocker
}

func TestService_RiskBlocksAddAndUnblock(t *testing.T) {
	svc, _ := blockAdminService(t, "t")

	added, err := svc.RiskBlocksAdd(context.Background(), RiskBlockAddRequest{
		IP: "::ffff:192.0.2.50", ConfirmIP: "192.0.2.50", Reason: "suspicious downloader", Actor: "ops",
	})
	require.NoError(t, err)
	assert.True(t, added.Changed)
	assert.Equal(t, "instance", added.Scope)
	assert.Equal(t, "manual", added.Entry.Source)
	assert.Equal(t, "ops", added.Entry.Actor)
	assert.Len(t, added.Entry.IP, 12)

	body, err := json.Marshal(added)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "192.0.2.50")

	listed, err := svc.RiskBlocksList(context.Background(), RiskBlocksListRequest{})
	require.NoError(t, err)
	assert.True(t, listed.MutationsEnabled)
	require.Len(t, listed.Entries, 1)
	assert.Equal(t, added.Entry.IP, listed.Entries[0].IP)

	removed, err := svc.RiskBlocksUnblock(context.Background(), RiskBlockUnblockRequest{
		IP: "192.0.2.50", ConfirmIP: "192.0.2.50", Actor: "ops",
	})
	require.NoError(t, err)
	assert.True(t, removed.Changed)
	assert.False(t, removed.Entry.Blocked)
}

func TestService_RiskBlocksRejectsUnsafeRequests(t *testing.T) {
	tests := []struct {
		name string
		req  RiskBlockAddRequest
	}{
		{name: "invalid ip", req: RiskBlockAddRequest{IP: "bad", ConfirmIP: "bad", Reason: "x", Actor: "ops"}},
		{name: "cidr", req: RiskBlockAddRequest{IP: "192.0.2.0/24", ConfirmIP: "192.0.2.0/24", Reason: "x", Actor: "ops"}},
		{name: "confirmation mismatch", req: RiskBlockAddRequest{IP: "192.0.2.1", ConfirmIP: "192.0.2.2", Reason: "x", Actor: "ops"}},
		{name: "empty reason", req: RiskBlockAddRequest{IP: "192.0.2.1", ConfirmIP: "192.0.2.1", Actor: "ops"}},
		{name: "control character", req: RiskBlockAddRequest{IP: "192.0.2.1", ConfirmIP: "192.0.2.1", Reason: "bad\nreason", Actor: "ops"}},
		{name: "negative ttl", req: RiskBlockAddRequest{IP: "192.0.2.1", ConfirmIP: "192.0.2.1", TTLSeconds: -1, Reason: "x", Actor: "ops"}},
		{name: "ttl too large", req: RiskBlockAddRequest{IP: "192.0.2.1", ConfirmIP: "192.0.2.1", TTLSeconds: int64((25 * time.Hour) / time.Second), Reason: "x", Actor: "ops"}},
	}
	svc, _ := blockAdminService(t, "t")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.RiskBlocksAdd(context.Background(), tt.req)
			rpcErr, ok := AsRPCError(err)
			require.True(t, ok)
			assert.Equal(t, "VALIDATION_FAILED", rpcErr.Code)
		})
	}
}

func TestService_RiskBlocksRequiresExplicitMutationAuth(t *testing.T) {
	svc, _ := blockAdminService(t, "")
	_, err := svc.RiskBlocksAdd(context.Background(), RiskBlockAddRequest{
		IP: "192.0.2.1", ConfirmIP: "192.0.2.1", Reason: "x", Actor: "anonymous",
	})
	rpcErr, ok := AsRPCError(err)
	require.True(t, ok)
	assert.Equal(t, "MUTATION_AUTH_REQUIRED", rpcErr.Code)

	svc.cfg.Admin.MutationsEnabled = false
	_, err = svc.RiskBlocksAdd(context.Background(), RiskBlockAddRequest{})
	rpcErr, ok = AsRPCError(err)
	require.True(t, ok)
	assert.Equal(t, "MUTATIONS_DISABLED", rpcErr.Code)
}
