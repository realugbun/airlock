package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Reproduction from a security review of v0.2.1. A typo in an MCP allowlist
// must not become allow-all.
func TestRedTeam_UnknownMCPRuleFieldFailsConfigLoad(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "airlock.yaml")
	data := []byte(`
service: redteam
providers:
  env: {}
routes:
  - path_prefix: /mcp
    upstream: http://127.0.0.1:9999
    auth:
      type: none
    access_rules:
      - {action: ALLOW, method: POST, path: /}
    mcp_rules:
      allowed_tool: [safe_read]
`)
	require.NoError(t, os.WriteFile(configPath, data, 0o600))

	_, err := Load(configPath)
	require.Error(t, err, "unknown YAML keys must be rejected instead of silently disabling MCP filtering")
}
