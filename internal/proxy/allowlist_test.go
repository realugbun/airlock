package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper to reduce boilerplate
func rule(action, method, path string) AccessRuleInput {
	return AccessRuleInput{Action: action, Method: method, Path: path}
}

// --- No rules = allow all ---

func TestAccess_NoRulesAllowsAll(t *testing.T) {
	p, err := NewAccessPolicy(nil, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/anything"))
	assert.True(t, p.Allowed("DELETE", "/anything"))
}

// --- Explicit empty rules = deny all ---

func TestAccess_ExplicitEmptyDeniesAll(t *testing.T) {
	p, err := NewAccessPolicy(nil, true)
	require.NoError(t, err)
	assert.False(t, p.Allowed("GET", "/anything"))
	assert.False(t, p.Allowed("POST", "/anything"))
	assert.False(t, p.Allowed("DELETE", "/anything"))
}

// --- Allow-only (implicit deny at end) ---

func TestAccess_AllowOnly(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("ALLOW", "POST", "/v1/chat/completions"),
		rule("ALLOW", "POST", "/v1/embeddings"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("POST", "/v1/chat/completions"))
	assert.True(t, p.Allowed("POST", "/v1/embeddings"))
	assert.False(t, p.Allowed("GET", "/v1/chat/completions"))  // wrong method
	assert.False(t, p.Allowed("POST", "/v1/models"))            // not listed
	assert.False(t, p.Allowed("DELETE", "/v1/chat/completions")) // implicit deny
}

// --- Deny-then-allow (blocklist style) ---

func TestAccess_DenyThenAllow(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("DENY", "DELETE", "/**"),
		rule("DENY", "ALL", "/admin/**"),
		rule("ALLOW", "ALL", "/**"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/anything"))
	assert.True(t, p.Allowed("POST", "/users"))
	assert.True(t, p.Allowed("PUT", "/items/42"))
	assert.False(t, p.Allowed("DELETE", "/users/123"))      // first rule denies
	assert.False(t, p.Allowed("GET", "/admin/settings"))    // second rule denies
	assert.False(t, p.Allowed("DELETE", "/admin/settings")) // first rule denies
}

// --- Mixed: broad allow with deny exceptions ---

func TestAccess_DenyExceptionsBeforeAllow(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("DENY", "DELETE", "/api/users/*"),
		rule("DENY", "ALL", "/api/admin/**"),
		rule("ALLOW", "ALL", "/api/**"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/api/users/123"))
	assert.True(t, p.Allowed("POST", "/api/users"))
	assert.True(t, p.Allowed("PUT", "/api/users/123"))
	assert.False(t, p.Allowed("DELETE", "/api/users/123"))   // denied
	assert.False(t, p.Allowed("GET", "/api/admin/settings")) // denied
	assert.False(t, p.Allowed("GET", "/other"))               // no match = deny
}

// --- First match wins: order matters ---

func TestAccess_OrderMatters(t *testing.T) {
	// DENY before ALLOW — deny wins
	p1, err := NewAccessPolicy([]AccessRuleInput{
		rule("DENY", "GET", "/secret"),
		rule("ALLOW", "GET", "/secret"),
	}, false)
	require.NoError(t, err)
	assert.False(t, p1.Allowed("GET", "/secret"))

	// ALLOW before DENY — allow wins
	p2, err := NewAccessPolicy([]AccessRuleInput{
		rule("ALLOW", "GET", "/secret"),
		rule("DENY", "GET", "/secret"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p2.Allowed("GET", "/secret"))
}

// --- Glob patterns ---

func TestAccess_SingleSegmentWildcard(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("ALLOW", "GET", "/users/*/detail"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/users/123/detail"))
	assert.True(t, p.Allowed("GET", "/users/abc/detail"))
	assert.False(t, p.Allowed("GET", "/users/123/delete"))
	assert.False(t, p.Allowed("GET", "/users/123/detail/extra"))
	assert.False(t, p.Allowed("GET", "/users/detail"))
}

func TestAccess_MultiSegmentWildcard(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("ALLOW", "GET", "/repos/**"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/repos/foo/bar"))
	assert.True(t, p.Allowed("GET", "/repos/foo/bar/baz"))
	assert.True(t, p.Allowed("GET", "/repos"))
	assert.False(t, p.Allowed("GET", "/user"))
}

func TestAccess_MixedWildcards(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("ALLOW", "GET", "/api/*/files/**"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/api/v1/files/readme.md"))
	assert.True(t, p.Allowed("GET", "/api/v2/files/docs/guide/intro.md"))
	assert.False(t, p.Allowed("GET", "/api/v1/v2/files/readme.md"))
	assert.False(t, p.Allowed("GET", "/api/files/readme.md"))
}

// --- Real-world: GitHub API style ---

func TestAccess_GitHubStyle(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("DENY", "ALL", "/repos/*/settings"),
		rule("DENY", "DELETE", "/repos/**"),
		rule("ALLOW", "GET", "/repos/**"),
		rule("ALLOW", "GET", "/user"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/repos/myapp/issues"))
	assert.True(t, p.Allowed("GET", "/repos/myapp/pulls"))
	assert.True(t, p.Allowed("GET", "/user"))
	assert.False(t, p.Allowed("GET", "/repos/myapp/settings"))  // deny rule
	assert.False(t, p.Allowed("DELETE", "/repos/myapp"))         // deny rule
	assert.False(t, p.Allowed("POST", "/repos/myapp/issues"))   // no allow for POST
}

// --- Real-world: block destructive methods ---

func TestAccess_BlockDestructive(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("DENY", "DELETE", "/**"),
		rule("DENY", "PUT", "/**"),
		rule("ALLOW", "ALL", "/**"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/resources/42"))
	assert.True(t, p.Allowed("POST", "/resources"))
	assert.True(t, p.Allowed("PATCH", "/resources/42"))
	assert.False(t, p.Allowed("DELETE", "/resources/42"))
	assert.False(t, p.Allowed("PUT", "/resources/42"))
}

// --- ALL method ---

func TestAccess_ALLMethod(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		rule("ALLOW", "ALL", "/health"),
	}, false)
	require.NoError(t, err)
	assert.True(t, p.Allowed("GET", "/health"))
	assert.True(t, p.Allowed("POST", "/health"))
	assert.True(t, p.Allowed("DELETE", "/health"))
	assert.False(t, p.Allowed("GET", "/other"))
}

// --- Error cases ---

func TestAccess_ErrorMissingAction(t *testing.T) {
	_, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "", Method: "GET", Path: "/headers"},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "action is required")
}

func TestAccess_ErrorBadAction(t *testing.T) {
	_, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "MAYBE", Method: "GET", Path: "/headers"},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid action")
}

func TestAccess_ErrorBadMethod(t *testing.T) {
	_, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "YOLO", Path: "/headers"},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid method")
}

func TestAccess_ErrorMissingMethod(t *testing.T) {
	_, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "", Path: "/headers"},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "method is required")
}

func TestAccess_ErrorMissingPath(t *testing.T) {
	_, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: ""},
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path is required")
}

// --- DP Matcher Correctness ---

func TestMatchPattern_DP_Correctness(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact match
		{"/v1/chat/completions", "/v1/chat/completions", true},
		{"/v1/chat/completions", "/v1/chat/other", false},
		{"/health", "/health", true},
		{"/health", "/healthz", false},

		// Single wildcard
		{"/users/*/profile", "/users/123/profile", true},
		{"/users/*/profile", "/users/abc/profile", true},
		{"/users/*/profile", "/users/profile", false},       // missing segment
		{"/users/*/profile", "/users/123/profile/x", false}, // extra segment

		// Doublestar
		{"/api/**", "/api", true},          // zero segments
		{"/api/**", "/api/v1", true},       // one segment
		{"/api/**", "/api/v1/x/y", true},   // many segments
		{"/api/**", "/other", false},       // different prefix
		{"/**", "/anything/at/all", true},  // root wildcard
		{"/**", "/", true},                 // root path
		{"/**", "", true},                  // empty path

		// Mixed wildcards
		{"/api/*/files/**", "/api/v1/files/readme.md", true},
		{"/api/*/files/**", "/api/v2/files/docs/guide", true},
		{"/api/*/files/**", "/api/v1/files", true},        // ** matches zero
		{"/api/*/files/**", "/api/files/readme.md", false}, // missing * segment

		// Doublestar in middle
		{"/**/end", "/a/b/c/end", true},
		{"/**/end", "/end", true},
		{"/**/end", "/a/end", true},
		{"/**/end", "/a/b/nope", false},
		{"/start/**/end", "/start/end", true},          // ** matches zero
		{"/start/**/end", "/start/a/b/c/end", true},
		{"/start/**/end", "/start/a/b/c/nope", false},

		// Multiple doublestars (DP handles without backtracking)
		{"/**/*/**", "/a/b/c", true},
		{"/**/x/**", "/a/x/b", true},
		{"/**/x/**", "/a/b/c", false},

		// Path normalization: interior // collapsed
		{"/v1/chat/completions", "/v1//chat/completions", true},
		{"/v1/chat/completions", "/v1///chat///completions", true},
		{"/users/*/profile", "/users//profile", false}, // // collapses to 2 segments, need 3

		// Edge cases
		{"", "", true},
		{"", "/foo", false},
		{"/", "/", true},
		{"/a", "/b", false},
	}

	for _, tt := range tests {
		got := matchPattern(tt.pattern, tt.path)
		assert.Equal(t, tt.want, got, "matchPattern(%q, %q)", tt.pattern, tt.path)
	}
}

func TestSplitPath_Normalization(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"/v1/chat/completions", []string{"v1", "chat", "completions"}},
		{"//v1//chat//", []string{"v1", "chat"}},
		{"/v1///chat///completions", []string{"v1", "chat", "completions"}},
		{"", nil},
		{"/", nil},
		{"//", nil},
		{"///", nil},
		{"/a", []string{"a"}},
		{"a/b", []string{"a", "b"}},
	}

	for _, tt := range tests {
		got := splitPath(tt.input)
		assert.Equal(t, tt.want, got, "splitPath(%q)", tt.input)
	}
}
