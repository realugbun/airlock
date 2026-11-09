package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shadowConfig builds a config whose routes have the given prefixes, in order.
func shadowConfig(prefixes ...string) string {
	content := `
service: "test-svc"
strict: false
providers:
  env: {}
routes:
`
	for _, p := range prefixes {
		content += `  - path_prefix: "` + p + `"
    upstream: "https://example.com"
    auth:
      type: none
    access_rules:
      - action: ALLOW
        method: ALL
        path: "/**"
`
	}
	return content
}

func loadShadowConfig(t *testing.T, prefixes ...string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(shadowConfig(prefixes...)), 0600))
	_, err := Load(path)
	return err
}

func TestLoadConfig_RejectsShadowedRoute(t *testing.T) {
	err := loadShadowConfig(t, "/api", "/api/v2")
	require.Error(t, err)
	// The error names both routes.
	assert.Contains(t, err.Error(), "/api/v2")
	assert.Contains(t, err.Error(), "route 0 (/api)")
	assert.Contains(t, err.Error(), "route 1 (/api/v2)")
}

func TestLoadConfig_RejectsShadowedRouteVariants(t *testing.T) {
	for _, prefixes := range [][]string{
		{"/api", "/api/v2"},
		{"/api/", "/api/v2"},
		{"/api", "/api/v2/"},
		{"/api", "/api"},
		{"/api", "/api/"},
		{"/", "/api"},
		{"/openai", "/anthropic", "/", "/mcp"},
		{"/a", "/b", "/a/b"},
	} {
		err := loadShadowConfig(t, prefixes...)
		assert.Error(t, err, "%v", prefixes)
		if err != nil {
			assert.Contains(t, err.Error(), "can never match", "%v", prefixes)
		}
	}
}

func TestLoadConfig_AllowsUnshadowedRoutes(t *testing.T) {
	for _, prefixes := range [][]string{
		{"/git", "/github"},
		{"/github", "/git"},
		{"/api/v2", "/api"},
		{"/openai", "/anthropic", "/mcp"},
		{"/openai", "/anthropic", "/"},
		{"/api", "/apifoo"},
		{"/"},
	} {
		assert.NoError(t, loadShadowConfig(t, prefixes...), "%v", prefixes)
	}
}
