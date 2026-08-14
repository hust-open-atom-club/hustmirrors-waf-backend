package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const managedSourceTestYAML = `pow:
  public_salt: source-test-salt
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
  enabled: false
logging:
  level: info
  format: json
`

func TestLoadWithSourceManagedGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(managedSourceTestYAML), 0o600))

	explicit, err := LoadWithSource(path, true)
	require.NoError(t, err)
	assert.True(t, explicit.Explicit)
	assert.True(t, explicit.Managed)
	assert.Equal(t, []byte(managedSourceTestYAML), explicit.Raw)
	assert.Equal(t, path, explicit.Path)

	auto, err := LoadWithSource(path, false)
	require.NoError(t, err)
	assert.False(t, auto.Explicit)
	assert.False(t, auto.Managed)
	assert.Equal(t, []byte(managedSourceTestYAML), auto.Raw)
}

func TestLoadWithSourceRejectsExplicitEmptyPath(t *testing.T) {
	_, err := LoadWithSource("", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestLoadWithSourceSymlinkIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	link := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(target, []byte(managedSourceTestYAML), 0o600))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	loaded, err := LoadWithSource(link, true)
	require.NoError(t, err)
	assert.False(t, loaded.Managed)
}

func TestLoadRawFromBytesRejectsUnknownAndDuplicateFields(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "unknown field", raw: managedSourceTestYAML + "unknown_section:\n  enabled: true\n"},
		{name: "duplicate key", raw: "pow:\n  public_salt: one\n  public_salt: two\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadRawFromBytes([]byte(tt.raw))
			require.Error(t, err)
		})
	}
}
