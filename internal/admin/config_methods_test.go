package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/configstore"
)

const (
	configOldSecretCanary = "phase3-old-secret-canary"
	configNewSecretCanary = "phase3-new-secret-canary"
)

type configTestFixture struct {
	svc   *Service
	store *configstore.Store
	path  string
}

func TestConfigMethods_MutationGateAndUnmanaged(t *testing.T) {
	raw := configTestYAML(configOldSecretCanary, "info", false)

	tests := []struct {
		name      string
		configure func(*config.Config)
		state     func(*testing.T) ConfigState
		code      string
	}{
		{
			name: "mutations disabled",
			configure: func(cfg *config.Config) {
				cfg.Admin.MutationsEnabled = false
			},
			state: func(t *testing.T) ConfigState { return newManagedConfigStore(t, raw).store },
			code:  "MUTATIONS_DISABLED",
		},
		{
			name: "authenticated mutations required",
			configure: func(cfg *config.Config) {
				cfg.Admin.Auth.Token = ""
			},
			state: func(t *testing.T) ConfigState { return newManagedConfigStore(t, raw).store },
			code:  "MUTATION_AUTH_REQUIRED",
		},
		{
			name: "config writes disabled",
			configure: func(cfg *config.Config) {
				cfg.Admin.ConfigManagement.Enabled = false
			},
			state: func(t *testing.T) ConfigState { return newManagedConfigStore(t, raw).store },
			code:  "CONFIG_WRITES_DISABLED",
		},
		{
			name:      "missing config state",
			configure: func(*config.Config) {},
			state:     func(*testing.T) ConfigState { return nil },
			code:      "CONFIG_SOURCE_UNMANAGED",
		},
		{
			name:      "unmanaged config store",
			configure: func(*config.Config) {},
			state: func(t *testing.T) ConfigState {
				store, err := configstore.New("", []byte(raw), false)
				require.NoError(t, err)
				return store
			},
			code: "CONFIG_SOURCE_UNMANAGED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configMutationTestConfig()
			tt.configure(cfg)
			svc, err := New(Options{Config: cfg, ConfigState: tt.state(t)})
			require.NoError(t, err)

			_, err = svc.ConfigDraftSave(context.Background(), ConfigDraftSaveRequest{
				BaseRevision: 1,
				ConfigYAML:   raw,
			})
			requireRPCCode(t, err, tt.code)
		})
	}

	svc, err := New(Options{Config: configMutationTestConfig()})
	require.NoError(t, err)
	_, err = svc.ConfigDraftGet(context.Background(), ConfigDraftGetRequest{DraftID: "missing"})
	requireRPCCode(t, err, "CONFIG_SOURCE_UNMANAGED")
}

func TestConfigMethods_DraftSaveGetCASAndSecretRedaction(t *testing.T) {
	fx := newManagedConfigFixture(t, configTestYAML(configOldSecretCanary, "info", false))
	candidate := configEditableTestYAML("debug", false)

	_, err := fx.svc.ConfigDraftSave(context.Background(), ConfigDraftSaveRequest{
		BaseRevision: 1,
		ConfigYAML:   configTestYAML(configNewSecretCanary, "debug", false),
	})
	requireRPCCode(t, err, "SECRET_PLACEHOLDER_INVALID")

	saved, err := fx.svc.ConfigDraftSave(context.Background(), ConfigDraftSaveRequest{
		BaseRevision: 1,
		ConfigYAML:   candidate,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, saved.DraftID)
	assert.Equal(t, uint64(1), saved.DraftRevision)
	assert.Equal(t, uint64(1), saved.BaseRevision)
	assert.False(t, saved.Validated)
	assertSecretsAbsent(t, saved)

	got, err := fx.svc.ConfigDraftGet(context.Background(), ConfigDraftGetRequest{DraftID: saved.DraftID})
	require.NoError(t, err)
	assert.Equal(t, saved.DraftID, got.DraftID)
	assert.Equal(t, saved.DraftRevision, got.DraftRevision)
	assertSecretsAbsent(t, got)

	_, err = fx.svc.ConfigDraftSave(context.Background(), ConfigDraftSaveRequest{
		DraftID:               saved.DraftID,
		ExpectedDraftRevision: 0,
		BaseRevision:          saved.BaseRevision,
		ConfigYAML:            configEditableTestYAML("warn", false),
	})
	requireRPCCode(t, err, "DRAFT_VERSION_CONFLICT")

	updated, err := fx.svc.ConfigDraftSave(context.Background(), ConfigDraftSaveRequest{
		DraftID:               saved.DraftID,
		ExpectedDraftRevision: saved.DraftRevision,
		BaseRevision:          saved.BaseRevision,
		ConfigYAML:            configEditableTestYAML("warn", false),
	})
	require.NoError(t, err)
	assert.Equal(t, saved.DraftID, updated.DraftID)
	assert.Equal(t, uint64(2), updated.DraftRevision)
	assert.False(t, updated.Validated)
	assertSecretsAbsent(t, updated)
}

func TestConfigMethods_ValidateDiffDangerousApplyHistoryAndRollback(t *testing.T) {
	initial := configTestYAML(configOldSecretCanary, "info", false)
	candidate := configEditableTestYAML("debug", true)
	fx := newManagedConfigFixture(t, initial)

	draft, err := fx.svc.ConfigDraftSave(context.Background(), ConfigDraftSaveRequest{
		BaseRevision: 1,
		ConfigYAML:   candidate,
	})
	require.NoError(t, err)
	assertSecretsAbsent(t, draft)

	_, err = fx.svc.ConfigApply(context.Background(), ConfigApplyRequest{
		DraftID:          draft.DraftID,
		DraftRevision:    draft.DraftRevision,
		ExpectedRevision: draft.BaseRevision,
		Acknowledged:     true,
	})
	requireRPCCode(t, err, "PREVIEW_STALE")

	_, err = fx.svc.ConfigDiff(context.Background(), ConfigDiffRequest{
		DraftID:       draft.DraftID,
		DraftRevision: draft.DraftRevision,
	})
	requireRPCCode(t, err, "VALIDATION_REQUIRED")

	validated, err := fx.svc.ConfigValidate(context.Background(), ConfigValidateRequest{
		DraftID:       draft.DraftID,
		DraftRevision: draft.DraftRevision,
	})
	require.NoError(t, err)
	assert.True(t, validated.OK, "problems: %v", validated.Problems)
	assert.True(t, validated.Valid)
	assert.True(t, validated.RestartRequired)

	diff, err := fx.svc.ConfigDiff(context.Background(), ConfigDiffRequest{
		DraftID:       draft.DraftID,
		DraftRevision: draft.DraftRevision,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, diff.PreviewID)
	assert.Equal(t, "critical", diff.Danger)
	assert.True(t, diff.RestartRequired)
	assert.NotEmpty(t, diff.ConfirmationPhrase)
	assertSecretsAbsent(t, diff)

	for _, change := range diff.Changes {
		assert.False(t, change.Sensitive, "KEEP placeholders must not create secret changes: %s", change.Path)
	}

	applyRequest := ConfigApplyRequest{
		DraftID:            draft.DraftID,
		DraftRevision:      draft.DraftRevision,
		PreviewID:          diff.PreviewID,
		ExpectedRevision:   diff.BaseRevision,
		Reason:             "exercise dangerous configuration apply",
		ConfirmationPhrase: diff.ConfirmationPhrase,
		Actor:              "phase3-test",
	}
	_, err = fx.svc.ConfigApply(context.Background(), applyRequest)
	requireRPCCode(t, err, "CONFIRMATION_REQUIRED")

	applyRequest.Acknowledged = true
	applyRequest.ConfirmationPhrase = "wrong phrase"
	_, err = fx.svc.ConfigApply(context.Background(), applyRequest)
	requireRPCCode(t, err, "CONFIRMATION_INVALID")

	applyRequest.ConfirmationPhrase = diff.ConfirmationPhrase
	applied, err := fx.svc.ConfigApply(context.Background(), applyRequest)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), applied.PreviousRevision)
	assert.Equal(t, uint64(2), applied.Revision)
	assert.False(t, applied.RuntimeApplied)
	assert.True(t, applied.RestartRequired)

	onDisk, err := os.ReadFile(fx.path)
	require.NoError(t, err)
	assert.Contains(t, string(onDisk), configOldSecretCanary)
	assert.NotContains(t, string(onDisk), configNewSecretCanary)
	assert.NotContains(t, string(onDisk), "${SECRET:KEEP}")
	assert.Contains(t, string(onDisk), "bypass_all: true")
	assert.Contains(t, string(onDisk), "level: debug")
	status := fx.store.Status()
	assert.Equal(t, uint64(2), status.CurrentRevision)
	assert.True(t, status.PendingRestart)

	history, err := fx.svc.ConfigHistory(context.Background(), ConfigHistoryRequest{Limit: 10})
	require.NoError(t, err)
	require.Len(t, history.Entries, 2)
	assert.Equal(t, uint64(2), history.Entries[0].Revision)
	assert.Equal(t, "apply", history.Entries[0].Action)
	assert.Equal(t, "phase3-test", history.Entries[0].Actor)
	assert.Equal(t, "exercise dangerous configuration apply", history.Entries[0].Reason)
	assert.True(t, history.Entries[0].RestartRequired)
	assertSecretsAbsent(t, history)

	for _, revision := range []uint64{1, 2} {
		item, getErr := fx.svc.ConfigHistoryGet(context.Background(), ConfigHistoryGetRequest{Revision: revision})
		require.NoError(t, getErr)
		assertSecretsAbsent(t, item)
	}

	_, err = fx.svc.ConfigRollback(context.Background(), ConfigRollbackRequest{
		TargetRevision:   1,
		ExpectedRevision: 2,
		Acknowledged:     true,
		Reason:           "rollback requires a preview",
	})
	requireRPCCode(t, err, "PREVIEW_STALE")

	rollbackPreview, err := fx.svc.ConfigDiff(context.Background(), ConfigDiffRequest{TargetRevision: 1})
	require.NoError(t, err)
	assert.NotEmpty(t, rollbackPreview.PreviewID)
	assert.NotEmpty(t, rollbackPreview.ConfirmationPhrase)
	assertSecretsAbsent(t, rollbackPreview)

	rollbackRequest := ConfigRollbackRequest{
		TargetRevision:     1,
		PreviewID:          rollbackPreview.PreviewID,
		ExpectedRevision:   rollbackPreview.BaseRevision,
		Reason:             "restore bootstrap configuration",
		ConfirmationPhrase: rollbackPreview.ConfirmationPhrase,
		Actor:              "phase3-test",
	}
	_, err = fx.svc.ConfigRollback(context.Background(), rollbackRequest)
	requireRPCCode(t, err, "CONFIRMATION_REQUIRED")

	rollbackRequest.Acknowledged = true
	rolledBack, err := fx.svc.ConfigRollback(context.Background(), rollbackRequest)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), rolledBack.PreviousRevision)
	assert.Equal(t, uint64(3), rolledBack.Revision)
	assert.Positive(t, rolledBack.ChangeCount)
	assert.NotEmpty(t, rolledBack.Danger)
	assert.False(t, rolledBack.RuntimeApplied)
	assert.True(t, rolledBack.RestartRequired)

	onDisk, err = os.ReadFile(fx.path)
	require.NoError(t, err)
	assert.Equal(t, initial, string(onDisk))

	history, err = fx.svc.ConfigHistory(context.Background(), ConfigHistoryRequest{Limit: 10})
	require.NoError(t, err)
	require.Len(t, history.Entries, 3)
	assert.Equal(t, "rollback", history.Entries[0].Action)
	assert.Equal(t, uint64(1), history.Entries[0].RollbackTarget)
	assertSecretsAbsent(t, history)
}

func TestConfigMethods_ApplyDetectsExternalConflict(t *testing.T) {
	initial := configTestYAML(configOldSecretCanary, "info", false)
	candidate := configTestYAML(configOldSecretCanary, "warn", false)
	fx := newManagedConfigFixture(t, initial)

	draft, err := fx.svc.ConfigDraftSave(context.Background(), ConfigDraftSaveRequest{
		BaseRevision: 1,
		ConfigYAML:   candidate,
	})
	require.NoError(t, err)
	validated, err := fx.svc.ConfigValidate(context.Background(), ConfigValidateRequest{
		DraftID:       draft.DraftID,
		DraftRevision: draft.DraftRevision,
	})
	require.NoError(t, err)
	require.True(t, validated.Valid, "problems: %v", validated.Problems)
	diff, err := fx.svc.ConfigDiff(context.Background(), ConfigDiffRequest{
		DraftID:       draft.DraftID,
		DraftRevision: draft.DraftRevision,
	})
	require.NoError(t, err)

	external := configTestYAML("external-secret", "error", false)
	require.NoError(t, os.WriteFile(fx.path, []byte(external), 0o600))

	_, err = fx.svc.ConfigApply(context.Background(), ConfigApplyRequest{
		DraftID:          draft.DraftID,
		DraftRevision:    draft.DraftRevision,
		PreviewID:        diff.PreviewID,
		ExpectedRevision: diff.BaseRevision,
		Acknowledged:     true,
		Actor:            "phase3-test",
	})
	requireRPCCode(t, err, "CONFIG_VERSION_CONFLICT")

	onDisk, readErr := os.ReadFile(fx.path)
	require.NoError(t, readErr)
	assert.Equal(t, external, string(onDisk))
	assert.Equal(t, uint64(1), fx.store.Status().CurrentRevision)
}

func newManagedConfigFixture(t *testing.T, raw string) configTestFixture {
	t.Helper()
	storeFixture := newManagedConfigStore(t, raw)
	svc, err := New(Options{Config: configMutationTestConfig(), ConfigState: storeFixture.store})
	require.NoError(t, err)
	return configTestFixture{svc: svc, store: storeFixture.store, path: storeFixture.path}
}

func newManagedConfigStore(t *testing.T, raw string) configTestFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
	store, err := configstore.New(path, []byte(raw), true)
	require.NoError(t, err)
	return configTestFixture{store: store, path: path}
}

func configMutationTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Admin.MutationsEnabled = true
	cfg.Admin.Auth.Token = "t"
	cfg.Admin.ConfigManagement.Enabled = true
	return cfg
}

func configEditableTestYAML(level string, bypassAll bool) string {
	return configTestYAML("${SECRET:KEEP}", level, bypassAll)
}

func configTestYAML(secret, level string, bypassAll bool) string {
	return fmt.Sprintf(`server:
  listen: 127.0.0.1:8080
pow:
  enabled: true
  bypass_all: %t
  public_salt: %q
  modes:
    ip_bound:
      enabled: true
    generic:
      enabled: false
storage:
  driver: memory
  counter_driver: memory
risk_control:
  enabled: false
admin:
  enabled: true
  listen: 127.0.0.1:8081
  auth:
    token: %q
  mutations_enabled: true
  config_management:
    enabled: true
logging:
  level: %s
  format: json
  log_salt: %q
`, bypassAll, secret, secret, level, secret)
}

func requireRPCCode(t *testing.T, err error, code string) {
	t.Helper()
	require.Error(t, err)
	rpcErr, ok := AsRPCError(err)
	require.True(t, ok, "expected RPCError, got %T: %v", err, err)
	assert.Equal(t, code, rpcErr.Code)
}

func assertSecretsAbsent(t *testing.T, value interface{}) {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	for _, secret := range []string{configOldSecretCanary, configNewSecretCanary, "external-secret"} {
		assert.NotContains(t, string(encoded), secret)
	}
}

func findConfigChange(t *testing.T, changes []ConfigDiffChange, path string) ConfigDiffChange {
	t.Helper()
	for _, change := range changes {
		if change.Path == path {
			return change
		}
	}
	t.Fatalf("configuration diff does not contain %q", path)
	return ConfigDiffChange{}
}
