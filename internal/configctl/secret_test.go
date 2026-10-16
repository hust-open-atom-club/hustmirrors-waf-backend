package configctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactYAML_PreservesOrderCommentsAndIndent(t *testing.T) {
	raw := []byte(`# top comment
server:
  listen: "127.0.0.1:8080"

pow:
  # salt drives the canonical string
  public_salt: "secret-salt"
  allow_empty_salt: true

storage:
  redis:
    password: "hunter2"
`)
	out := RedactYAML(raw)

	assert.Contains(t, out, "# top comment")
	assert.Contains(t, out, "# salt drives the canonical string", "comments must survive redaction")
	assert.Contains(t, out, "\n  listen: \"127.0.0.1:8080\"\n", "2-space indentation must survive")
	assert.Contains(t, out, "public_salt: ${SECRET:KEEP}")
	assert.Contains(t, out, "password: ${SECRET:KEEP}")
	assert.Contains(t, out, "allow_empty_salt: true")

	server := strings.Index(out, "server:")
	pow := strings.Index(out, "pow:")
	storage := strings.Index(out, "storage:")
	require.NotEqual(t, -1, server)
	assert.True(t, pow > server && storage > pow, "key order must survive redaction:\n%s", out)
}

// TestRedactYAML_ExampleConfigKeepsLayout pins the behaviour on the shipped
// example: the file is the template operators copy to /etc, so redaction must
// not strip its comments, reorder keys or re-indent it.
func TestRedactYAML_ExampleConfigKeepsLayout(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "config.example.yaml"))
	require.NoError(t, err)

	out := RedactYAML(raw)

	assert.Contains(t, out, "public_salt: ${SECRET:KEEP}")
	assert.Contains(t, out, "dsn: ${SECRET:KEEP}")
	assert.Contains(t, out, "allowed_previous_salts: ${SECRET:KEEP}")
	assert.Contains(t, out, "log_salt: ${SECRET:KEEP}")

	assert.Contains(t, out, "# Mode A: bound to the client IP")
	assert.Contains(t, out, "# Extension-based protection")

	assert.Less(t, strings.Index(out, "server:"), strings.Index(out, "pow:"))
	assert.Less(t, strings.Index(out, "pow:"), strings.Index(out, "protection:"))
	assert.Less(t, strings.Index(out, "protection:"), strings.Index(out, "risk_control:"))

	assert.Contains(t, out, "listen: \"127.0.0.1:8080\"")
	assert.Contains(t, out, "max_uses: 5")
	assert.NotContains(t, out, "2025-demo-salt", "the salt value must not leak")
}

// TestRedactYAML_CRLFInputKeepsCommentsIntact guards the \r handling: with
// CRLF input the parser kept a carriage return on every comment line, and
// re-encoding spliced a blank line between each pair of comment lines.
func TestRedactYAML_CRLFInputKeepsCommentsIntact(t *testing.T) {
	raw := []byte("# first\r\n# second\r\nkey: value\r\n")
	out := RedactYAML(raw)
	assert.Contains(t, out, "# first\n# second\n", "comment lines must stay adjacent")
	assert.NotContains(t, out, "# first\n\n# second")
}

func TestMergeSecretPlaceholders(t *testing.T) {
	base := []byte(`pow:
  public_salt: "live-salt"
  allowed_previous_salts: []
logging:
  log_salt: ""
`)

	t.Run("keep restores the live value", func(t *testing.T) {
		edited := "pow:\n  public_salt: ${SECRET:KEEP}\n  allowed_previous_salts: ${SECRET:KEEP}\nlogging:\n  log_salt: ${SECRET:KEEP}\n"
		out, err := mergeSecretPlaceholders(edited, base)
		require.NoError(t, err)
		assert.Contains(t, string(out), "live-salt")
		assert.Contains(t, string(out), "allowed_previous_salts: []")
		assert.NotContains(t, string(out), "${SECRET:")
	})

	t.Run("clear empties the value", func(t *testing.T) {
		edited := "pow:\n  public_salt: ${SECRET:CLEAR}\n  allowed_previous_salts: ${SECRET:CLEAR}\nlogging:\n  log_salt: ${SECRET:CLEAR}\n"
		out, err := mergeSecretPlaceholders(edited, base)
		require.NoError(t, err)
		assert.NotContains(t, string(out), "live-salt")
		assert.Contains(t, string(out), "allowed_previous_salts: []")
	})

	t.Run("literal edit is rejected", func(t *testing.T) {
		edited := "pow:\n  public_salt: types-it-by-hand\n  allowed_previous_salts: []\nlogging:\n  log_salt: \"\"\n"
		_, err := mergeSecretPlaceholders(edited, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "placeholders")
	})

	t.Run("removed sensitive field is rejected", func(t *testing.T) {
		edited := "pow:\n  allowed_previous_salts: ${SECRET:KEEP}\nlogging:\n  log_salt: ${SECRET:KEEP}\n"
		_, err := mergeSecretPlaceholders(edited, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "was removed")
	})

	t.Run("placeholder on a non-sensitive field is rejected", func(t *testing.T) {
		edited := "pow:\n  public_salt: ${SECRET:KEEP}\n  allowed_previous_salts: ${SECRET:KEEP}\n  algorithm: ${SECRET:KEEP}\nlogging:\n  log_salt: ${SECRET:KEEP}\n"
		_, err := mergeSecretPlaceholders(edited, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not sensitive")
	})
}

// TestManager_EditRoundTripKeepsComments is the end-to-end guarantee: after
// redact -> edit -> merge -> apply, the file on disk still carries its
// comments and key order while the edited value and the live secret are both
// correct.
func TestManager_EditRoundTripKeepsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := `# managed by the team
server:
  listen: "127.0.0.1:8080"

pow:
  public_salt: "live-salt"
  # raised during the 2026 incident
  max_sign_length: 128
`
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
	m, err := Open(path)
	require.NoError(t, err)

	_, redacted, err := m.Redacted()
	require.NoError(t, err)
	assert.Contains(t, redacted, "# managed by the team")
	assert.Contains(t, redacted, "# raised during the 2026 incident")
	assert.Contains(t, redacted, "public_salt: ${SECRET:KEEP}")

	edited := strings.Replace(redacted, "max_sign_length: 128", "max_sign_length: 256", 1)
	candidate, err := m.MergeSecrets(edited)
	require.NoError(t, err)

	plan, err := m.Plan(candidate, "apply")
	require.NoError(t, err)
	require.Len(t, plan.Changes, 1)

	_, err = m.Apply(candidate, plan, "tweak sign length", "tester", "apply", 0)
	require.NoError(t, err)

	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(onDisk), "# managed by the team", "comments must survive an edit")
	assert.Contains(t, string(onDisk), "# raised during the 2026 incident")
	assert.Contains(t, string(onDisk), "max_sign_length: 256")
	assert.Contains(t, string(onDisk), "live-salt", "the live secret must be restored")
	assert.NotContains(t, string(onDisk), "${SECRET:")
	assert.Less(t, strings.Index(string(onDisk), "server:"), strings.Index(string(onDisk), "pow:"))
}
