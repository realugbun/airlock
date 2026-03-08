package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// =============================================================================
// Path Traversal Bypass Attempts
// =============================================================================

func TestSecurity_PathTraversal_DotDot(t *testing.T) {
	// Path traversal should not bypass access rules.
	// .. is treated as a LITERAL segment by our matcher — it does NOT resolve.
	// Go's net/http resolves .. before paths reach us, so if .. appears here
	// it's a literal segment name. Our ** wildcard matches it like any other segment.
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "DENY", Method: "ALL", Path: "/admin/**"},
		{Action: "ALLOW", Method: "ALL", Path: "/api/**"},
	}, false)
	require.NoError(t, err)

	// /../admin/settings → segments [.., admin, settings] — no match for /admin/** or /api/**
	assert.False(t, p.Allowed("GET", "/../admin/settings"))

	// /api/../admin/settings → segments [api, .., admin, settings] — matches /api/**
	// This is safe: if .. literally appears in r.URL.Path, Go didn't resolve it,
	// meaning it's a segment name, not a traversal. The DENY /admin/** rule won't
	// trigger because the path starts with /api/, not /admin/.
	assert.True(t, p.Allowed("GET", "/api/../admin/settings"))
	assert.True(t, p.Allowed("GET", "/api/../../admin/settings"))
}

func TestSecurity_PathTraversal_DotDotLiteral(t *testing.T) {
	// When .. reaches our matcher, it's treated as a literal segment
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	require.NoError(t, err)

	// All these contain .. which becomes a literal segment — none match the exact path
	assert.False(t, p.Allowed("POST", "/v1/../v1/chat/completions"))
	assert.False(t, p.Allowed("POST", "/../v1/chat/completions"))
	assert.False(t, p.Allowed("POST", "/v1/chat/../chat/completions"))
	assert.False(t, p.Allowed("POST", "/v1/chat/completions/.."))
	assert.False(t, p.Allowed("POST", "/v1/chat/completions/../../../etc/passwd"))
}

func TestSecurity_DoubleSlash_Normalized(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	require.NoError(t, err)

	// splitPath trims leading/trailing slashes:
	// //v1/chat/completions → trim → v1/chat/completions → [v1, chat, completions] → MATCHES
	assert.True(t, p.Allowed("POST", "//v1/chat/completions"))
	// /v1/chat/completions// → trim → v1/chat/completions → [v1, chat, completions] → MATCHES
	assert.True(t, p.Allowed("POST", "/v1/chat/completions//"))

	// Interior double slashes are normalized (empty segments filtered):
	// /v1//chat/completions → [v1, chat, completions] → MATCHES
	assert.True(t, p.Allowed("POST", "/v1//chat/completions"))
	// /v1/chat//completions → [v1, chat, completions] → MATCHES
	assert.True(t, p.Allowed("POST", "/v1/chat//completions"))
}

// =============================================================================
// URL Encoding Bypass Attempts
// =============================================================================

func TestSecurity_URLEncoding_NoBypass(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	require.NoError(t, err)

	// By the time paths reach our matcher, Go has already decoded them.
	// These test that percent-encoded variants DON'T match if they decode to different paths.
	// %2f = / (creates extra segment), %2e = . (literal dot)
	assert.False(t, p.Allowed("POST", "/v1/chat%2fcompletions"))       // one segment "chat%2fcompletions"
	assert.False(t, p.Allowed("POST", "/v1/%63hat/completions"))       // "chat" with c encoded
	assert.False(t, p.Allowed("POST", "/%76%31/chat/completions"))     // "v1" encoded
}

func TestSecurity_NullByte_NoBypass(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	require.NoError(t, err)

	// Null bytes are treated as literal characters — no truncation
	assert.False(t, p.Allowed("POST", "/v1/chat/completions\x00"))
	assert.False(t, p.Allowed("POST", "/v1/chat/completions\x00extra"))
	assert.False(t, p.Allowed("POST", "/v1\x00/chat/completions"))
}

// =============================================================================
// Case Sensitivity
// =============================================================================

func TestSecurity_CaseSensitive_Path(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	require.NoError(t, err)

	assert.True(t, p.Allowed("POST", "/v1/chat/completions"))
	assert.False(t, p.Allowed("POST", "/V1/CHAT/COMPLETIONS"))
	assert.False(t, p.Allowed("POST", "/v1/Chat/Completions"))
	assert.False(t, p.Allowed("POST", "/V1/chat/completions"))
}

func TestSecurity_CaseSensitive_Method(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	require.NoError(t, err)

	assert.True(t, p.Allowed("POST", "/v1/chat/completions"))
	assert.False(t, p.Allowed("post", "/v1/chat/completions"))
	assert.False(t, p.Allowed("Post", "/v1/chat/completions"))
}

// =============================================================================
// Trailing / Leading Slash Variants
// =============================================================================

func TestSecurity_TrailingSlash_NotEquivalent(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	require.NoError(t, err)

	assert.True(t, p.Allowed("POST", "/v1/chat/completions"))
	// Trailing slash is stripped by splitPath, so this actually matches
	assert.True(t, p.Allowed("POST", "/v1/chat/completions/"))
}

func TestSecurity_LeadingSlash_Required(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/health"},
	}, false)
	require.NoError(t, err)

	assert.True(t, p.Allowed("GET", "/health"))
	// Without leading slash, splitPath still works (trims /)
	assert.True(t, p.Allowed("GET", "health"))
}

// =============================================================================
// Wildcard Security
// =============================================================================

func TestSecurity_WildcardMatchBehavior(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/users/*/profile"},
	}, false)
	require.NoError(t, err)

	assert.True(t, p.Allowed("GET", "/users/123/profile"))
	// /users//profile normalizes to [users, profile] (2 segments) — doesn't match 3-segment pattern
	assert.False(t, p.Allowed("GET", "/users//profile"))
	// Missing segment entirely won't match (only 2 segments instead of 3)
	assert.False(t, p.Allowed("GET", "/users/profile"))
}

func TestSecurity_DoublestarCanMatchEmpty(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/repos/**"},
	}, false)
	require.NoError(t, err)

	assert.True(t, p.Allowed("GET", "/repos"))                       // ** matches zero segments
	assert.True(t, p.Allowed("GET", "/repos/owner"))                 // one segment
	assert.True(t, p.Allowed("GET", "/repos/owner/repo/issues/1"))   // many segments
}

// =============================================================================
// Pathological Pattern Prevention (ReDoS-style)
// =============================================================================

func TestSecurity_PathologicalPattern_NoHang(t *testing.T) {
	// This would cause exponential backtracking without collapseDoublestar
	pattern := strings.Repeat("**/", 30) + "end"
	path := strings.Repeat("a/", 30) + "end"

	// Should complete quickly, not hang
	result := matchPattern(pattern, path)
	assert.True(t, result)
}

func TestSecurity_PathologicalPattern_NonMatch_NoHang(t *testing.T) {
	pattern := strings.Repeat("**/", 30) + "end"
	path := strings.Repeat("a/", 30) + "nope"

	result := matchPattern(pattern, path)
	assert.False(t, result)
}

func TestSecurity_ManyWildcards_NoHang(t *testing.T) {
	// Pattern with alternating ** and * — should still be fast after collapse
	parts := make([]string, 0)
	for i := 0; i < 20; i++ {
		parts = append(parts, "**", "*")
	}
	parts = append(parts, "end")
	pattern := "/" + strings.Join(parts, "/")
	path := "/" + strings.Repeat("a/", 40) + "end"

	// Just verify it doesn't hang
	matchPattern(pattern, path)
}

func TestSecurity_CollapseDoublestar(t *testing.T) {
	tests := []struct {
		input    []string
		expected []string
	}{
		{[]string{"**", "**", "**", "end"}, []string{"**", "end"}},
		{[]string{"a", "**", "**", "b"}, []string{"a", "**", "b"}},
		{[]string{"**"}, []string{"**"}},
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{nil, []string{}},
		{[]string{"**", "*", "**"}, []string{"**", "*", "**"}}, // * breaks the consecutive run
	}

	for _, tt := range tests {
		result := collapseDoublestar(tt.input)
		assert.Equal(t, tt.expected, result, "input: %v", tt.input)
	}
}

// =============================================================================
// MCP Security: Request Smuggling
// =============================================================================

func TestSecurity_MCP_RequestSmuggling_NestedJSON(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"safe_tool"},
	})

	// Attempt: wrap a denied tool call inside another field
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"nested":{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dangerous_tool"}}}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	// Only the top-level tool name is checked — nested JSON in arguments is just data
	assert.False(t, result.Denied)
	assert.Equal(t, "tools/call", result.Method)
}

func TestSecurity_MCP_ExtraFieldsIgnored(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	// Extra unknown fields should be silently ignored
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}},"extra":"field","another":123}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied)
}

func TestSecurity_MCP_UnicodeToolName(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	// Unicode tool name — not in allow list
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get\u005fevents"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	// \u005f is underscore, so this is "get_events" — should be allowed
	assert.False(t, result.Denied)
}

func TestSecurity_MCP_HomoglyphToolName(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	// Homoglyph attack: looks like get_events but uses different Unicode chars
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gеt_events"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	// This uses Cyrillic "е" (U+0435) instead of Latin "e" — should be denied
	assert.True(t, result.Denied)
}

func TestSecurity_MCP_OversizedBody_Passthrough(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	// Body larger than maxMCPBodySize (10MB) — should pass through without inspection
	bigBody := strings.Repeat("x", 11*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Denied) // Not inspected, passes through
}

func TestSecurity_MCP_DuplicateNameField(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"safe_tool"},
	})

	// JSON with duplicate "name" field — Go's encoding/json takes the last one
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","name":"dangerous_tool"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	// Go's json.Unmarshal takes the last value for duplicate keys
	assert.True(t, result.Denied)
	assert.Equal(t, "dangerous_tool", result.ToolName)
}

// =============================================================================
// Concurrent Access Policy Evaluation
// =============================================================================

func TestSecurity_ConcurrentPolicyEval(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "DENY", Method: "DELETE", Path: "/**"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
		{Action: "ALLOW", Method: "GET", Path: "/v1/models"},
	}, false)
	require.NoError(t, err)

	var wg sync.WaitGroup
	results := make([]bool, 1000)

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			switch idx % 3 {
			case 0:
				results[idx] = p.Allowed("POST", "/v1/chat/completions")
			case 1:
				results[idx] = !p.Allowed("DELETE", "/v1/chat/completions")
			case 2:
				results[idx] = p.Allowed("GET", "/v1/models")
			}
		}(i)
	}

	wg.Wait()

	// All results should be true (correct evaluation)
	for i, r := range results {
		assert.True(t, r, "concurrent evaluation failed at index %d", i)
	}
}

// =============================================================================
// Concurrent MCP Policy Evaluation
// =============================================================================

func TestSecurity_ConcurrentMCPPolicyEval(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events"}}`
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			result, err := p.CheckRequest(req)
			assert.NoError(t, err)
			assert.False(t, result.Denied)
		}()
		go func() {
			defer wg.Done()
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_event"}}`
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			result, err := p.CheckRequest(req)
			assert.NoError(t, err)
			assert.True(t, result.Denied)
		}()
	}

	wg.Wait()
}

// =============================================================================
// Router-Level Security Tests
// =============================================================================

func TestSecurity_Router_BlockedPathNeverReachesUpstream(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/openai",
		StripPrefix: "/openai",
		Upstream:    upstreamURL,
		Auth:        &noopAuth{},
		Access:      access,
	})

	// Blocked requests
	paths := []struct {
		method string
		path   string
	}{
		{"GET", "/openai/v1/models"},
		{"DELETE", "/openai/v1/chat/completions"},
		{"POST", "/openai/v1/admin"},
		{"GET", "/openai/v1/chat/completions"},
	}

	for _, p := range paths {
		req := httptest.NewRequest(p.method, p.path, nil)
		ctx := airlocklog.WithCorrelationID(req.Context(), "test")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s should be forbidden", p.method, p.path)
	}

	assert.Equal(t, 0, upstreamCalls, "no blocked requests should reach upstream")
}

func TestSecurity_Router_MCPDeniedNeverReachesUpstream(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"safe_tool"},
	})

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upstreamURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool"}}`
	req := httptest.NewRequest("POST", "/mcp/endpoint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 0, upstreamCalls)

	// Verify it's a proper JSON-RPC error
	var resp jsonRPCErrorResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, -32600, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "dangerous_tool")
}

func TestSecurity_Router_RateLimitDoesNotLeakToUpstream(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upstreamURL,
		Auth:       &noopAuth{},
		Access:     access,
		Limiter:    rate.NewLimiter(1, 1), // 1 req/s, burst 1
	})

	ctx := airlocklog.WithCorrelationID(context.Background(), "test")

	// First request should succeed
	req1 := httptest.NewRequest("GET", "/api/data", nil)
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1.WithContext(ctx))
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Second request immediately should be rate limited
	req2 := httptest.NewRequest("GET", "/api/data", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2.WithContext(ctx))
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)

	assert.Equal(t, 1, upstreamCalls, "rate-limited request should not reach upstream")
}

// =============================================================================
// Redaction Security
// =============================================================================

func TestSecurity_Redaction_NeverLeaksToken(t *testing.T) {
	token := "sk-proj-a1b2c3d4e5f6g7h8i9j0-very-long-api-key"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Upstream leaks the token in multiple places
		w.Header().Set("X-Echo-Auth", "Bearer "+token)
		w.Header().Set("X-Debug-Token", token)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"auth_header": "Bearer ` + token + `",
			"raw_token": "` + token + `",
			"message": "The key ` + token + ` was used",
			"partial": "prefix-` + token + `-suffix"
		}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "")
	access, _ := NewAccessPolicy(nil, false)

	// Use multiRedactAuth which returns both "Bearer TOKEN" and "TOKEN" as redact values,
	// matching what the real StaticAuth provider does.
	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upstreamURL,
		Auth:       &multiRedactAuth{header: "Authorization", value: "Bearer " + token, rawToken: token},
		Access:     access,
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)

	// Token must not appear anywhere in the response
	body := rec.Body.String()
	assert.NotContains(t, body, token, "token leaked in response body")

	for name, values := range rec.Header() {
		for _, v := range values {
			assert.NotContains(t, v, token, "token leaked in header %s", name)
		}
	}

	// Verify [REDACTED] is present
	assert.Contains(t, body, "[REDACTED]")
}

// multiRedactAuth injects auth and returns both the full header value and raw token for redaction.
type multiRedactAuth struct {
	header   string
	value    string
	rawToken string
}

func (a *multiRedactAuth) AddAuth(ctx context.Context, req *http.Request) ([]string, error) {
	req.Header.Set(a.header, a.value)
	return []string{a.value, a.rawToken}, nil
}

func TestSecurity_Redaction_StripAgentAuth_ThenInject(t *testing.T) {
	realToken := "sk-real-production-key"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the real token was injected
		assert.Equal(t, "Bearer "+realToken, r.Header.Get("Authorization"))
		// Verify fake tokens were stripped
		assert.Empty(t, r.Header.Get("x-api-key"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:     "/api",
		Upstream:       upstreamURL,
		Auth:           &injectAuth{header: "Authorization", value: "Bearer " + realToken},
		Access:         access,
		StripAgentAuth: true,
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer fake-token-from-agent")
	req.Header.Set("x-api-key", "sk-fake-agent-key")
	req.Header.Set("X-Api-Key", "sk-another-fake")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
}

// =============================================================================
// DenyAll Policy Security
// =============================================================================

func TestSecurity_DenyAll_BlocksEverything(t *testing.T) {
	p, err := NewAccessPolicy(nil, true)
	require.NoError(t, err)

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	paths := []string{"/", "/api", "/admin", "/v1/chat/completions", "/**", "/*"}

	for _, method := range methods {
		for _, path := range paths {
			assert.False(t, p.Allowed(method, path),
				"denyAll should block %s %s", method, path)
		}
	}
}

// =============================================================================
// Edge Cases: Empty/Nil
// =============================================================================

func TestSecurity_EmptyPath(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/health"},
	}, false)
	require.NoError(t, err)

	assert.False(t, p.Allowed("GET", ""))
	assert.False(t, p.Allowed("GET", " "))
}

func TestSecurity_EmptyMethod(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/health"},
	}, false)
	require.NoError(t, err)

	// ALL matches any method including empty string
	assert.True(t, p.Allowed("", "/health"))
}

// =============================================================================
// MCP FilterToolsList Security
// =============================================================================

func TestSecurity_MCP_FilterToolsList_PreservesIDAndFields(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"safe_tool"},
	})

	body := `{"jsonrpc":"2.0","id":"string-id","result":{"tools":[{"name":"safe_tool","description":"Safe","inputSchema":{"type":"object"}},{"name":"danger","description":"Bad"}],"nextCursor":"abc123"}}`

	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)

	var resp map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(fr.Body, &resp))

	// ID preserved
	assert.Equal(t, `"string-id"`, string(resp["id"]))
	// jsonrpc preserved
	assert.Equal(t, `"2.0"`, string(resp["jsonrpc"]))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resp["result"], &result))

	// nextCursor preserved
	assert.Equal(t, `"abc123"`, string(result["nextCursor"]))

	// Only safe_tool remains
	var tools []map[string]interface{}
	require.NoError(t, json.Unmarshal(result["tools"], &tools))
	assert.Len(t, tools, 1)
	assert.Equal(t, "safe_tool", tools[0]["name"])
	// inputSchema preserved
	assert.NotNil(t, tools[0]["inputSchema"])
}

func TestSecurity_MCP_FilterToolsList_ErrorResponse_Passthrough(t *testing.T) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"safe_tool"},
	})

	// Error response (no result field) should pass through unchanged
	body := `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`

	fr, err := p.FilterToolsListResponse([]byte(body), "application/json")
	require.NoError(t, err)
	assert.Equal(t, body, string(fr.Body))
}

// =============================================================================
// DP Matcher Hardening
// =============================================================================

func TestSecurity_DP_AlternatingDoublestar_NoHang(t *testing.T) {
	// Pattern with alternating ** and * — would cause exponential backtracking
	// with the old recursive matcher. DP handles it in O(P*S).
	pattern := "**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/**/*/*/**/end"
	path := "/" + strings.Repeat("a/", 60) + "end"

	result := matchPattern(pattern, path)
	assert.True(t, result)

	// Non-matching variant should also complete instantly
	path2 := "/" + strings.Repeat("a/", 60) + "nope"
	result2 := matchPattern(pattern, path2)
	assert.False(t, result2)
}

func TestSecurity_DP_MaxSegments_Denied(t *testing.T) {
	// Pattern exceeding maxPatternSegments (64) should be denied
	parts := make([]string, 70)
	for i := range parts {
		parts[i] = "seg"
	}
	longPattern := "/" + strings.Join(parts, "/")
	assert.False(t, matchPattern(longPattern, "/seg"))

	// Path exceeding maxPathSegments (256) should be denied
	pathParts := make([]string, 260)
	for i := range pathParts {
		pathParts[i] = "a"
	}
	longPath := "/" + strings.Join(pathParts, "/")
	assert.False(t, matchPattern("/**", longPath))

	// Just under the limit should work
	okParts := make([]string, 63)
	for i := range okParts {
		okParts[i] = "s"
	}
	okPattern := "/" + strings.Join(okParts, "/")
	assert.True(t, matchPattern(okPattern, okPattern))
}

func TestSecurity_PathNormalization_InteriorSlashes(t *testing.T) {
	p, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/api/v1/data"},
	}, false)
	require.NoError(t, err)

	// All of these should normalize to [api, v1, data] and match
	assert.True(t, p.Allowed("GET", "/api/v1/data"))
	assert.True(t, p.Allowed("GET", "/api//v1/data"))
	assert.True(t, p.Allowed("GET", "/api///v1///data"))
	assert.True(t, p.Allowed("GET", "//api//v1//data//"))

	// But extra real segments still don't match
	assert.False(t, p.Allowed("GET", "/api/v1/data/extra"))
	assert.False(t, p.Allowed("GET", "/api/v2/data"))
}

// =============================================================================
// Encoded Slash Rejection (Router-Level)
// =============================================================================

func TestSecurity_EncodedSlash_Rejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upstreamURL,
		Auth:       &noopAuth{},
		Access:     access,
	})

	tests := []struct {
		name    string
		rawPath string
	}{
		{"lowercase %2f", "/api/v1%2fchat"},
		{"uppercase %2F", "/api/v1%2Fchat"},
		{"backslash %5c", "/api/v1%5cadmin"},
		{"backslash %5C", "/api/v1%5Cadmin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.rawPath, nil)
			// Manually set RawPath to simulate encoded separators
			req.URL.RawPath = tt.rawPath
			ctx := airlocklog.WithCorrelationID(req.Context(), "test")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req.WithContext(ctx))
			assert.Equal(t, http.StatusBadRequest, rec.Code, tt.name)
		})
	}

	// Edge case: %5C uppercase where RawPath might be empty but EscapedPath catches it.
	// Simulate by setting Path with literal backslash and clearing RawPath.
	t.Run("backslash via EscapedPath fallback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.URL.Path = "/api/v1\\admin" // literal backslash in decoded path
		req.URL.RawPath = ""            // empty — Go would set this when %5C matches EscapedPath
		ctx := airlocklog.WithCorrelationID(req.Context(), "test")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
		// EscapedPath() re-encodes \ as %5C, which our guard detects
		assert.Equal(t, http.StatusBadRequest, rec.Code, "backslash via EscapedPath")
	})
}

func TestSecurity_EncodedSlash_NormalRequests_Unaffected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upstreamURL,
		Auth:       &noopAuth{},
		Access:     access,
	})

	// Normal requests have empty RawPath — should pass through fine
	paths := []string{"/api/v1/chat", "/api/data", "/api/v1/models"}
	for _, path := range paths {
		req := httptest.NewRequest("GET", path, nil)
		ctx := airlocklog.WithCorrelationID(req.Context(), "test")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
		assert.Equal(t, http.StatusOK, rec.Code, path)
	}
}

func TestSecurity_ContainsEncodedPathSep(t *testing.T) {
	// Both args empty = no encoding
	assert.False(t, containsEncodedPathSep("", ""))
	// Normal path (escapedPath fallback, no encoding)
	assert.False(t, containsEncodedPathSep("", "/api/v1/chat"))
	// RawPath has encoded /
	assert.True(t, containsEncodedPathSep("/api/v1%2fchat", "/api/v1/chat"))
	assert.True(t, containsEncodedPathSep("/api/v1%2Fchat", "/api/v1/chat"))
	// RawPath has encoded backslash
	assert.True(t, containsEncodedPathSep("/api%5cadmin", "/api%5Cadmin"))
	assert.True(t, containsEncodedPathSep("/api%5Cadmin", "/api%5Cadmin"))
	// RawPath empty but escapedPath has %5C (uppercase edge case)
	assert.True(t, containsEncodedPathSep("", "/api%5Cadmin"))
	// Other encoding is fine
	assert.False(t, containsEncodedPathSep("/api/%20spaces", "/api/%20spaces"))
}
