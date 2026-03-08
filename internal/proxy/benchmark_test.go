package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	"golang.org/x/time/rate"
)

// --- Access Policy Benchmarks ---

func BenchmarkAccessPolicy_ExactMatch(b *testing.B) {
	p, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Allowed("POST", "/v1/chat/completions")
	}
}

func BenchmarkAccessPolicy_WildcardMatch(b *testing.B) {
	p, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/users/*/detail"},
	}, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Allowed("GET", "/users/12345/detail")
	}
}

func BenchmarkAccessPolicy_DoublestarMatch(b *testing.B) {
	p, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/repos/**"},
	}, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Allowed("GET", "/repos/owner/repo/issues/123/comments")
	}
}

func BenchmarkAccessPolicy_ManyRules(b *testing.B) {
	rules := []AccessRuleInput{
		{Action: "DENY", Method: "DELETE", Path: "/**"},
		{Action: "DENY", Method: "ALL", Path: "/admin/**"},
		{Action: "DENY", Method: "ALL", Path: "/internal/**"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/embeddings"},
		{Action: "ALLOW", Method: "GET", Path: "/v1/models"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/images/generations"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/audio/transcriptions"},
	}
	p, _ := NewAccessPolicy(rules, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Allowed("POST", "/v1/chat/completions")
	}
}

func BenchmarkAccessPolicy_ImplicitDeny(b *testing.B) {
	rules := []AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/embeddings"},
	}
	p, _ := NewAccessPolicy(rules, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This path won't match any rule — exercises full scan + implicit deny
		p.Allowed("GET", "/v1/unknown/endpoint")
	}
}

func BenchmarkAccessPolicy_DenyAll(b *testing.B) {
	p, _ := NewAccessPolicy(nil, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Allowed("POST", "/v1/chat/completions")
	}
}

func BenchmarkAccessPolicy_NoRulesAllowAll(b *testing.B) {
	p, _ := NewAccessPolicy(nil, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Allowed("POST", "/anything/goes/here")
	}
}

// --- Pattern Matching Benchmarks ---

func BenchmarkMatchPattern_Exact(b *testing.B) {
	for i := 0; i < b.N; i++ {
		matchPattern("/v1/chat/completions", "/v1/chat/completions")
	}
}

func BenchmarkMatchPattern_SingleWildcard(b *testing.B) {
	for i := 0; i < b.N; i++ {
		matchPattern("/users/*/detail", "/users/12345/detail")
	}
}

func BenchmarkMatchPattern_Doublestar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		matchPattern("/repos/**", "/repos/owner/repo/issues/123/comments")
	}
}

func BenchmarkMatchPattern_MixedWildcards(b *testing.B) {
	for i := 0; i < b.N; i++ {
		matchPattern("/api/*/files/**", "/api/v1/files/docs/guide/intro.md")
	}
}

func BenchmarkMatchPattern_LongPath_NoMatch(b *testing.B) {
	path := "/" + strings.Repeat("segment/", 50) + "end"
	for i := 0; i < b.N; i++ {
		matchPattern("/v1/chat/completions", path)
	}
}

func BenchmarkMatchPattern_PathologicalPattern(b *testing.B) {
	// After collapse, this is just "**" + end
	pattern := strings.Repeat("**/", 20) + "end"
	path := strings.Repeat("a/", 20) + "end"
	for i := 0; i < b.N; i++ {
		matchPattern(pattern, path)
	}
}

// --- MCP Policy Benchmarks ---

func BenchmarkMCPCheckRequest_AllowedTool(b *testing.B) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars", "create_event", "update_event"},
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		_, _ = p.CheckRequest(req)
	}
}

func BenchmarkMCPCheckRequest_DeniedTool(b *testing.B) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_event","arguments":{}}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		_, _ = p.CheckRequest(req)
	}
}

func BenchmarkMCPCheckRequest_NonToolMethod(b *testing.B) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		_, _ = p.CheckRequest(req)
	}
}

func BenchmarkMCPCheckRequest_BatchRequest(b *testing.B) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})
	body := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events"}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_calendars"}},
		{"jsonrpc":"2.0","id":3,"method":"initialize"}
	]`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		_, _ = p.CheckRequest(req)
	}
}

func BenchmarkMCPFilterToolsList_Small(b *testing.B) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})
	body := []byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_events","description":"Get calendar events"},{"name":"delete_event","description":"Delete an event"},{"name":"list_calendars","description":"List calendars"},{"name":"send_message","description":"Send a message"}]}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.FilterToolsListResponse(body, "application/json")
	}
}

func BenchmarkMCPFilterToolsList_Large(b *testing.B) {
	p, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"tool_1", "tool_5", "tool_10"},
	})

	// Build a tools list with 50 tools
	var tools []map[string]string
	for i := 0; i < 50; i++ {
		tools = append(tools, map[string]string{
			"name":        "tool_" + strings.Repeat("x", 0) + string(rune('0'+i/10)) + string(rune('0'+i%10)),
			"description": "Description for tool " + string(rune('0'+i/10)) + string(rune('0'+i%10)),
		})
	}
	// Fix tool names to use numbers
	for i := range tools {
		tools[i]["name"] = "tool_" + itoa(i)
	}
	result := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"result":  map[string]interface{}{"tools": tools},
	}
	body, _ := json.Marshal(result)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.FilterToolsListResponse(body, "application/json")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// --- Redaction Benchmarks ---

func BenchmarkRedact_NoSecrets(b *testing.B) {
	data := []byte(strings.Repeat("This is a normal response body without any secrets. ", 100))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newRedactingReader(io.NopCloser(bytes.NewReader(data)), nil)
		_, _ = io.ReadAll(r)
	}
}

func BenchmarkRedact_SingleToken(b *testing.B) {
	token := "sk-secret-token-abc123"
	data := []byte(`{"response": "Here is your auth: Bearer ` + token + ` enjoy"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newRedactingReader(io.NopCloser(bytes.NewReader(data)), []string{token})
		_, _ = io.ReadAll(r)
	}
}

func BenchmarkRedact_MultipleTokens(b *testing.B) {
	tokens := []string{
		"sk-secret-token-abc123",
		"Bearer sk-secret-token-abc123",
		"another-secret-value",
	}
	data := []byte(`{"auth": "Bearer sk-secret-token-abc123", "key": "another-secret-value", "data": "` + strings.Repeat("normal content ", 50) + `"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newRedactingReader(io.NopCloser(bytes.NewReader(data)), tokens)
		_, _ = io.ReadAll(r)
	}
}

func BenchmarkRedact_LargeBody(b *testing.B) {
	token := "sk-secret-key-to-redact"
	// 100KB body with token in the middle
	prefix := strings.Repeat("A", 50*1024)
	suffix := strings.Repeat("B", 50*1024)
	data := []byte(prefix + token + suffix)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newRedactingReader(io.NopCloser(bytes.NewReader(data)), []string{token})
		_, _ = io.ReadAll(r)
	}
}

func BenchmarkRedact_StreamingChunks(b *testing.B) {
	token := "sk-secret-123"
	data := []byte(strings.Repeat(`data: {"token": "sk-secret-123"}\n\n`, 20))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newRedactingReader(
			io.NopCloser(&tinyReader{data: data, chunkSize: 64}),
			[]string{token},
		)
		_, _ = io.ReadAll(r)
	}
}

func BenchmarkSSERedact_StreamingEvents(b *testing.B) {
	token := "sk-secret-123"
	var buf bytes.Buffer
	for i := 0; i < 20; i++ {
		if i%3 == 0 {
			fmt.Fprintf(&buf, "data: {\"chunk\": %d, \"token\": \"%s\"}\n\n", i, token)
		} else {
			fmt.Fprintf(&buf, "data: {\"chunk\": %d, \"content\": \"safe\"}\n\n", i)
		}
	}
	data := buf.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newSSERedactingReader(io.NopCloser(bytes.NewReader(data)), []string{token})
		_, _ = io.ReadAll(r)
	}
}

func BenchmarkSSERedact_TinyChunks(b *testing.B) {
	token := "sk-secret-123"
	var buf bytes.Buffer
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&buf, "data: {\"chunk\": %d, \"token\": \"%s\"}\n\n", i, token)
	}
	data := buf.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newSSERedactingReader(
			io.NopCloser(&tinyReader{data: data, chunkSize: 32}),
			[]string{token},
		)
		_, _ = io.ReadAll(r)
	}
}

func BenchmarkRedactHeaders(b *testing.B) {
	headers := http.Header{
		"X-Debug-Auth":   {"Bearer sk-secret-token"},
		"Content-Type":   {"application/json"},
		"Server":         {"nginx/1.25"},
		"X-Request-Id":   {"abc123"},
		"X-Custom-Token": {"sk-secret-token"},
	}
	secrets := []string{"sk-secret-token", "Bearer sk-secret-token"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Copy headers since redaction is in-place
		h := make(http.Header, len(headers))
		for k, v := range headers {
			h[k] = append([]string{}, v...)
		}
		redactHeaderValues(h, secrets)
	}
}

// --- HTTP Proxy End-to-End Benchmarks ---

type noopAuth struct{}

func (a *noopAuth) AddAuth(ctx context.Context, req *http.Request) ([]string, error) {
	return nil, nil
}

type injectAuth struct {
	header string
	value  string
}

func (a *injectAuth) AddAuth(ctx context.Context, req *http.Request) ([]string, error) {
	req.Header.Set(a.header, a.value)
	return []string{a.value}, nil
}

func BenchmarkHTTPProxy_Passthrough(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upstreamURL,
		Auth:       &noopAuth{},
		Access:     access,
	})

	req := httptest.NewRequest("POST", "/api/v1/chat", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "bench-corr")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
	}
}

func BenchmarkHTTPProxy_WithAuth(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upstreamURL,
		Auth:       &injectAuth{header: "Authorization", value: "Bearer sk-test-token"},
		Access:     access,
	})

	req := httptest.NewRequest("POST", "/api/v1/chat", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "bench-corr")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
	}
}

func BenchmarkHTTPProxy_WithRedaction(b *testing.B) {
	token := "sk-super-secret-key-12345"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"auth": "Bearer ` + token + `", "data": "some response content"}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upstreamURL,
		Auth:       &injectAuth{header: "Authorization", value: "Bearer " + token},
		Access:     access,
	})

	req := httptest.NewRequest("POST", "/api/v1/chat", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "bench-corr")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
	}
}

func BenchmarkHTTPProxy_WithRateLimit(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upstreamURL,
		Auth:       &noopAuth{},
		Access:     access,
		Limiter:    rate.NewLimiter(rate.Inf, 0), // no actual limit, just overhead
	})

	req := httptest.NewRequest("POST", "/api/v1/chat", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "bench-corr")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
	}
}

func BenchmarkHTTPProxy_MCPToolCall(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars", "create_event"},
	})

	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upstreamURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`
	ctx := airlocklog.WithCorrelationID(context.Background(), "bench-corr")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/mcp/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}

func BenchmarkHTTPProxy_MCPToolsListFilter(b *testing.B) {
	toolsResp := `{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events","description":"Get events"},` +
		`{"name":"delete_event","description":"Delete an event"},` +
		`{"name":"list_calendars","description":"List calendars"},` +
		`{"name":"send_message","description":"Send a message"},` +
		`{"name":"create_event","description":"Create an event"}` +
		`]}}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toolsResp))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upstreamURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	ctx := airlocklog.WithCorrelationID(context.Background(), "bench-corr")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/mcp/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}

func BenchmarkHTTPProxy_FullPipeline(b *testing.B) {
	token := "sk-secret-key-production"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "upstream/1.0")
		w.WriteHeader(http.StatusOK)
		// Echo back something that includes the token (worst case for redaction)
		_, _ = w.Write([]byte(`{"model":"gpt-4","response":"some text with ` + token + ` leaked"}`))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "DENY", Method: "DELETE", Path: "/**"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/embeddings"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:           "/openai",
		StripPrefix:          "/openai",
		Upstream:             upstreamURL,
		Auth:                 &injectAuth{header: "Authorization", value: "Bearer " + token},
		Access:               access,
		Limiter:              rate.NewLimiter(rate.Inf, 0),
		StripResponseHeaders: []string{"Server"},
		StripAgentAuth:       true,
		Timeout:              30 * time.Second,
	})

	ctx := airlocklog.WithCorrelationID(context.Background(), "bench-corr")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer fake-agent-token")
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}

// --- Idle Timeout Benchmarks ---

func BenchmarkIdleTimeoutReader(b *testing.B) {
	data := bytes.Repeat([]byte("data: chunk\n\n"), 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		r := newIdleTimeoutReader(
			io.NopCloser(bytes.NewReader(data)),
			5*time.Second,
			cancel,
		)
		_, _ = io.ReadAll(r)
		_ = r.Close()
		cancel()
		_ = ctx
	}
}

// --- Health Check Benchmark ---

func BenchmarkHealthCheck(b *testing.B) {
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})

	req := httptest.NewRequest("GET", "/healthz", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
}

// --- Route Matching Benchmark ---

func BenchmarkRouteMatching_FirstRoute(b *testing.B) {
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	upstream, _ := url.Parse("http://localhost:9999")
	access, _ := NewAccessPolicy(nil, false)

	for _, prefix := range []string{"/openai", "/anthropic", "/mcp", "/github", "/linear"} {
		router.AddRoute(&Route{
			PathPrefix: prefix,
			Upstream:   upstream,
			Auth:       &noopAuth{},
			Access:     access,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.matchRoute("/openai/v1/chat/completions")
	}
}

func BenchmarkRouteMatching_LastRoute(b *testing.B) {
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	upstream, _ := url.Parse("http://localhost:9999")
	access, _ := NewAccessPolicy(nil, false)

	for _, prefix := range []string{"/openai", "/anthropic", "/mcp", "/github", "/linear"} {
		router.AddRoute(&Route{
			PathPrefix: prefix,
			Upstream:   upstream,
			Auth:       &noopAuth{},
			Access:     access,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.matchRoute("/linear/issues/123")
	}
}

func BenchmarkRouteMatching_NoMatch(b *testing.B) {
	logger := airlocklog.NewLogger(devNull{}, "bench", "bench-agent")
	router := NewRouter(RouterConfig{AgentID: "bench-agent", Logger: logger})
	upstream, _ := url.Parse("http://localhost:9999")
	access, _ := NewAccessPolicy(nil, false)

	for _, prefix := range []string{"/openai", "/anthropic", "/mcp", "/github", "/linear"} {
		router.AddRoute(&Route{
			PathPrefix: prefix,
			Upstream:   upstream,
			Auth:       &noopAuth{},
			Access:     access,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.matchRoute("/unknown/path")
	}
}

// --- CollapseDoublestar Benchmark ---

func BenchmarkCollapseDoublestar(b *testing.B) {
	parts := make([]string, 40)
	for i := range parts {
		parts[i] = "**"
	}
	parts = append(parts, "end")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collapseDoublestar(parts)
	}
}

// Helper for benchmark setup validation
func TestBenchmarkSetup(t *testing.T) {
	// Ensure benchmark helpers compile and run correctly
	auth := &injectAuth{header: "Authorization", value: "Bearer test"}
	req := httptest.NewRequest("GET", "/", nil)
	redact, err := auth.AddAuth(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, []string{"Bearer test"}, redact)
	require.Equal(t, "Bearer test", req.Header.Get("Authorization"))
}
