package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
listen: ":9090"
service: "github.com/realugbun/airlock"
agent_id: "test-agent-01"
providers:
  env: {}
routes:
  - path_prefix: "/openai"
    upstream: "https://api.openai.com"
    strip_prefix: "/openai"
    auth:
      type: static
      token:
        from: env
        key: "OPENAI_API_KEY"
      header: "Authorization"
      prefix: "Bearer "
    rate_limit:
      rps: 10
      burst: 20
    access_rules:
      - action: ALLOW
        method: POST
        path: /v1/chat/completions
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, ":9090", cfg.Listen)
	assert.Equal(t, "test-agent-01", cfg.AgentID)
	assert.Len(t, cfg.Routes, 1)
	assert.Equal(t, "/openai", cfg.Routes[0].PathPrefix)
	assert.Equal(t, "static", cfg.Routes[0].Auth.Type)
	assert.Equal(t, float64(10), cfg.Routes[0].RateLimit.RPS)
}

func TestLoadConfig_DefaultListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, ":8080", cfg.Listen)
}

func TestLoadConfig_MissingService(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service is required")
}

func TestLoadConfig_NoRoutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test"
routes: []
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one route")
}

func TestLoadConfig_InvalidAuthType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test"
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: unknown
      header: "Authorization"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown auth type")
}

func TestLoadConfig_StripResponseHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    strip_response_headers:
      - Server
      - X-Powered-By
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"Server", "X-Powered-By"}, cfg.Routes[0].StripResponseHeaders)
}

func TestLoadConfig_Timeouts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    timeout: "120s"
    idle_timeout: "30s"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "120s", cfg.Routes[0].Timeout)
	assert.Equal(t, "30s", cfg.Routes[0].IdleTimeout)
}

func TestLoadConfig_AgentAuthAndExtraHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/anthropic"
    upstream: "https://api.anthropic.com"
    strip_agent_auth: true
    extra_headers:
      anthropic-beta: "oauth-2025-04-20"
      anthropic-version: "2023-06-01"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Routes[0].StripAgentAuth)
	assert.Equal(t, "oauth-2025-04-20", cfg.Routes[0].ExtraHeaders["anthropic-beta"])
	assert.Equal(t, "2023-06-01", cfg.Routes[0].ExtraHeaders["anthropic-version"])
}

func TestLoadConfig_MCPRules_AllowedTools(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/mcp"
    upstream: "http://localhost:3000"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    mcp_rules:
      allowed_tools:
        - get_events
        - list_calendars
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.Routes[0].MCPRules)
	assert.Equal(t, []string{"get_events", "list_calendars"}, cfg.Routes[0].MCPRules.AllowedTools)
	assert.Empty(t, cfg.Routes[0].MCPRules.DeniedTools)
}

func TestLoadConfig_MCPRules_DeniedTools(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/mcp"
    upstream: "http://localhost:3000"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    mcp_rules:
      denied_tools:
        - delete_event
        - send_message
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.Routes[0].MCPRules)
	assert.Equal(t, []string{"delete_event", "send_message"}, cfg.Routes[0].MCPRules.DeniedTools)
	assert.Empty(t, cfg.Routes[0].MCPRules.AllowedTools)
}

func TestLoadConfig_MCPRules_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/mcp"
    upstream: "http://localhost:3000"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    mcp_rules: {}
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.Routes[0].MCPRules)
	assert.Empty(t, cfg.Routes[0].MCPRules.AllowedTools)
	assert.Empty(t, cfg.Routes[0].MCPRules.DeniedTools)
}

func TestLoadConfig_MCPRules_BothLists_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/mcp"
    upstream: "http://localhost:3000"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    mcp_rules:
      allowed_tools:
        - get_events
      denied_tools:
        - delete_event
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mcp_rules cannot have both")
}

func TestLoadConfig_MCPRules_Omitted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Nil(t, cfg.Routes[0].MCPRules)
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	assert.Error(t, err)
}

func TestLoadConfig_StrictDefault_AuthNoRules_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_rules required")
	assert.Contains(t, err.Error(), "strict: false")
}

func TestLoadConfig_StrictFalse_AuthNoRules_OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Len(t, cfg.Routes, 1)
}

func TestLoadConfig_StrictDefault_WithRules_OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    access_rules:
      - action: ALLOW
        method: POST
        path: /v1/chat/completions
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Len(t, cfg.Routes, 1)
}

func TestLoadConfig_StrictTrue_Explicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
strict: true
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_rules required")
}

func TestLoadConfig_StrictDefault_ExplicitEmptyRules_OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/api"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    access_rules: []
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Len(t, cfg.Routes, 1)
	assert.NotNil(t, cfg.Routes[0].AccessRules)
	assert.Len(t, cfg.Routes[0].AccessRules, 0)
}

// =============================================================================
// path_regex validation
// =============================================================================

func TestLoadConfig_PathRegex_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/upstream"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    access_rules:
      - { action: ALLOW, method: PUT, path_regex: '/v1/records/REC-\d+' }
      - { action: DENY,  method: ALL, path: /** }
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, `/v1/records/REC-\d+`, cfg.Routes[0].AccessRules[0].PathRegex)
	assert.Equal(t, "", cfg.Routes[0].AccessRules[0].Path)
}

func TestLoadConfig_PathRegex_BothPathAndRegex_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/upstream"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    access_rules:
      - { action: ALLOW, method: GET, path: /foo, path_regex: '/foo' }
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one of path or path_regex")
	assert.Contains(t, err.Error(), "/upstream")
	assert.Contains(t, err.Error(), "access_rules[0]")
}

func TestLoadConfig_PathRegex_NeitherSet_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/upstream"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    access_rules:
      - { action: ALLOW, method: GET }
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one of path or path_regex is required")
}

func TestLoadConfig_PathRegex_TooLong_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	long := make([]byte, MaxPathRegexLen+1)
	for i := range long {
		long[i] = 'a'
	}
	content := `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/upstream"
    upstream: "https://api.example.com"
    auth:
      type: static
      token:
        from: env
        key: "KEY"
      header: "Authorization"
      prefix: "Bearer "
    access_rules:
      - { action: ALLOW, method: GET, path_regex: '` + string(long) + `' }
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

// --- auth.type: none -------------------------------------------------------

// noneAuthConfig builds a single-route config whose auth block is `authBlock`.
func noneAuthConfig(authBlock string) string {
	return `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/media"
    upstream: "https://cdn.example.com"
    strip_prefix: "/media"
    strip_agent_auth: true
` + authBlock + `
    access_rules:
      - action: ALLOW
        method: GET
        path: /file/*/binary
      - action: DENY
        method: ALL
        path: /**
`
}

func loadNoneAuthConfig(t *testing.T, authBlock string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(noneAuthConfig(authBlock)), 0600))
	return Load(path)
}

func TestLoadConfig_AuthNone_Valid(t *testing.T) {
	cfg, err := loadNoneAuthConfig(t, "    auth:\n      type: none")
	require.NoError(t, err)
	require.Len(t, cfg.Routes, 1)
	assert.Equal(t, "none", cfg.Routes[0].Auth.Type)
	// No credential fields are populated for a passthrough route.
	assert.Nil(t, cfg.Routes[0].Auth.Token)
	assert.Empty(t, cfg.Routes[0].Auth.Header)
	// strip_agent_auth is orthogonal to auth type and must still be honoured.
	assert.True(t, cfg.Routes[0].StripAgentAuth)
}

// A "none" route that also names a credential is almost certainly a mistake:
// the author believes something is being injected when nothing is. Fail loudly
// at load rather than silently proxying unauthenticated.
func TestLoadConfig_AuthNone_RejectsCredentialFields(t *testing.T) {
	cases := map[string]string{
		"token":         "    auth:\n      type: none\n      token:\n        from: env\n        key: \"SOME_TOKEN\"",
		"header":        "    auth:\n      type: none\n      header: \"Authorization\"",
		"prefix":        "    auth:\n      type: none\n      prefix: \"Bearer \"",
		"token_url":     "    auth:\n      type: none\n      token_url: \"https://example.com/token\"",
		"scopes":        "    auth:\n      type: none\n      scopes: \"read\"",
		"client_id":     "    auth:\n      type: none\n      client_id:\n        from: env\n        key: \"CID\"",
		"client_secret": "    auth:\n      type: none\n      client_secret:\n        from: env\n        key: \"CSEC\"",
		"refresh_token": "    auth:\n      type: none\n      refresh_token:\n        from: env\n        key: \"RTOK\"",
	}
	for name, authBlock := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadNoneAuthConfig(t, authBlock)
			require.Error(t, err, "auth.type none with %s must be rejected", name)
			assert.Contains(t, err.Error(), "injects no credential")
		})
	}
}

// Regression: relaxing the header requirement for "none" must not relax it for
// the credential-injecting types.
func TestLoadConfig_AuthHeaderStillRequiredForStatic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
service: "test-svc"
providers:
  env: {}
routes:
  - path_prefix: "/x"
    upstream: "https://example.com"
    auth:
      type: static
      token:
        from: env
        key: "TOKEN"
    access_rules:
      - action: ALLOW
        method: GET
        path: /**
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth.header is required")
}
