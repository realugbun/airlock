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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// =============================================================================
// Multi-Route Integration Tests
// =============================================================================

func newMultiRouteRouter(t *testing.T, upstreams map[string]*httptest.Server) *Router {
	t.Helper()
	logger := airlocklog.NewLogger(devNull{}, "integration", "test-agent")
	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})

	for prefix, upstream := range upstreams {
		upstreamURL, err := url.Parse(upstream.URL)
		require.NoError(t, err)
		access, _ := NewAccessPolicy([]AccessRuleInput{
			{Action: "ALLOW", Method: "ALL", Path: "/**"},
		}, false)
		router.AddRoute(&Route{
			PathPrefix:  prefix,
			StripPrefix: prefix,
			Upstream:    upstreamURL,
			Auth:        &noopAuth{},
			Access:      access,
		})
	}

	return router
}

func TestIntegration_MultiRouteRouting(t *testing.T) {
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("openai:" + r.URL.Path))
	}))
	defer openai.Close()

	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("anthropic:" + r.URL.Path))
	}))
	defer anthropic.Close()

	router := newMultiRouteRouter(t, map[string]*httptest.Server{
		"/openai":    openai,
		"/anthropic": anthropic,
	})

	ctx := airlocklog.WithCorrelationID(context.Background(), "test")

	// Request to OpenAI route
	req1 := httptest.NewRequest("GET", "/openai/v1/models", nil)
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1.WithContext(ctx))
	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, "openai:/v1/models", rec1.Body.String())

	// Request to Anthropic route
	req2 := httptest.NewRequest("GET", "/anthropic/v1/messages", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2.WithContext(ctx))
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "anthropic:/v1/messages", rec2.Body.String())

	// No matching route
	req3 := httptest.NewRequest("GET", "/unknown/path", nil)
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3.WithContext(ctx))
	assert.Equal(t, http.StatusNotFound, rec3.Code)
}

// =============================================================================
// Config Reload (SetRoutes) Integration
// =============================================================================

func TestIntegration_SetRoutes_AtomicSwap(t *testing.T) {
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("v1"))
	}))
	defer upstream1.Close()

	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("v2"))
	}))
	defer upstream2.Close()

	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})

	// Initial routes
	up1URL, _ := url.Parse(upstream1.URL)
	access1, _ := NewAccessPolicy(nil, false)
	router.SetRoutes([]*Route{{
		PathPrefix: "/api",
		Upstream:   up1URL,
		Auth:       &noopAuth{},
		Access:     access1,
	}})

	ctx := airlocklog.WithCorrelationID(context.Background(), "test")

	// Verify v1
	req := httptest.NewRequest("GET", "/api/data", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))
	assert.Equal(t, "v1", rec.Body.String())

	// Swap routes
	up2URL, _ := url.Parse(upstream2.URL)
	access2, _ := NewAccessPolicy(nil, false)
	router.SetRoutes([]*Route{{
		PathPrefix: "/api",
		Upstream:   up2URL,
		Auth:       &noopAuth{},
		Access:     access2,
	}})

	// Verify v2
	req2 := httptest.NewRequest("GET", "/api/data", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2.WithContext(ctx))
	assert.Equal(t, "v2", rec2.Body.String())
}

func TestIntegration_SetRoutes_ConcurrentAccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})

	upURL, _ := url.Parse(upstream.URL)
	access, _ := NewAccessPolicy(nil, false)
	router.SetRoutes([]*Route{{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
	}})

	ctx := airlocklog.WithCorrelationID(context.Background(), "test")
	var wg sync.WaitGroup

	// Concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				req := httptest.NewRequest("GET", "/api/data", nil)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req.WithContext(ctx))
				// Should be 200 or 404 if routes are being swapped, never panic
				code := rec.Code
				if code != http.StatusOK && code != http.StatusNotFound {
					t.Errorf("unexpected status: %d", code)
				}
			}
		}()
	}

	// Concurrent writer (config reloads)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			newAccess, _ := NewAccessPolicy(nil, false)
			router.SetRoutes([]*Route{{
				PathPrefix: "/api",
				Upstream:   upURL,
				Auth:       &noopAuth{},
				Access:     newAccess,
			}})
		}()
	}

	wg.Wait()
}

// =============================================================================
// Concurrent Request Handling
// =============================================================================

func TestIntegration_ConcurrentRequests(t *testing.T) {
	var requestCount atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/openai",
		StripPrefix: "/openai",
		Upstream:    upURL,
		Auth:        &noopAuth{},
		Access:      access,
	})

	var wg sync.WaitGroup
	successCount := atomic.Int64{}
	blockedCount := atomic.Int64{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := airlocklog.WithCorrelationID(context.Background(), fmt.Sprintf("req-%d", idx))

			var req *http.Request
			if idx%2 == 0 {
				// Allowed request
				req = httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
			} else {
				// Blocked request
				req = httptest.NewRequest("GET", "/openai/v1/models", nil)
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req.WithContext(ctx))

			switch rec.Code {
			case http.StatusOK:
				successCount.Add(1)
			case http.StatusForbidden:
				blockedCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	assert.Equal(t, int64(50), successCount.Load(), "50 allowed requests should succeed")
	assert.Equal(t, int64(50), blockedCount.Load(), "50 blocked requests should be denied")
	assert.Equal(t, int64(50), requestCount.Load(), "only allowed requests should reach upstream")
}

// =============================================================================
// Rate Limiting Under Load
// =============================================================================

func TestIntegration_RateLimiting_BurstThenThrottle(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		Limiter:    rate.NewLimiter(10, 5), // 10 req/s, burst of 5
	})

	ctx := airlocklog.WithCorrelationID(context.Background(), "test")

	// Burst: first 5 should succeed
	successCount := 0
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/data", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code == http.StatusOK {
			successCount++
		}
	}
	assert.Equal(t, 5, successCount, "burst of 5 should all succeed")

	// Immediately send more — should be rate limited
	rateLimited := 0
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/data", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code == http.StatusTooManyRequests {
			rateLimited++
		}
	}
	assert.Greater(t, rateLimited, 0, "should have some rate-limited requests")
}

// =============================================================================
// Streaming Response with Redaction
// =============================================================================

func TestIntegration_StreamingRedaction(t *testing.T) {
	token := "sk-streaming-secret-key"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected Flusher")
		}

		events := []string{
			`data: {"chunk": 1, "content": "Hello"}`,
			`data: {"chunk": 2, "content": "Token is ` + token + `"}`,
			`data: {"chunk": 3, "content": "World"}`,
			`data: [DONE]`,
		}
		for _, evt := range events {
			_, _ = w.Write([]byte(evt + "\n\n"))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &multiRedactAuth{header: "Authorization", value: "Bearer " + token, rawToken: token},
		Access:     access,
	})

	req := httptest.NewRequest("GET", "/api/stream", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	body := rec.Body.String()
	assert.NotContains(t, body, token, "token must not appear in streamed response")
	assert.Contains(t, body, "[REDACTED]")
	assert.Contains(t, body, "Hello")
	assert.Contains(t, body, "World")
}

func TestIntegration_SSERedaction_EventDeliveryTiming(t *testing.T) {
	token := "sk-timing-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected Flusher")
		}

		events := []string{
			`data: {"chunk": 1, "content": "Hello"}`,
			`data: {"chunk": 2, "token": "` + token + `"}`,
			`data: {"chunk": 3, "content": "World"}`,
		}
		for _, evt := range events {
			_, _ = w.Write([]byte(evt + "\n\n"))
			flusher.Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &multiRedactAuth{header: "Authorization", value: "Bearer " + token, rawToken: token},
		Access:     access,
	})

	// Use a real HTTP server (not httptest.NewRecorder) to test streaming timing.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := airlocklog.WithCorrelationID(r.Context(), "timing-test")
		router.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/api/stream")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Read events and verify they arrive promptly (not starved by buffering).
	buf := make([]byte, 4096)
	var allData []byte
	eventCount := 0
	start := time.Now()
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			allData = append(allData, buf[:n]...)
			// Count complete events (terminated by \n\n).
			eventCount += strings.Count(string(buf[:n]), "\n\n")
		}
		if readErr != nil {
			break
		}
	}
	elapsed := time.Since(start)

	body := string(allData)
	assert.NotContains(t, body, token, "token must not appear in streamed response")
	assert.Contains(t, body, "[REDACTED]")
	assert.Contains(t, body, "Hello")
	assert.Contains(t, body, "World")
	assert.Equal(t, 3, eventCount, "should receive 3 SSE events")
	// With 50ms between events and 3 events, total should be ~100-150ms.
	// If events were starved by buffering, it would be much longer or events
	// would arrive all at once after the stream closes.
	assert.Less(t, elapsed, 2*time.Second, "events should arrive in real-time, not buffered")
}

func TestIntegration_SSERedaction_MultipleTokensInEvents(t *testing.T) {
	token := "sk-multi-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected Flusher")
		}

		events := []string{
			`data: {"chunk": 1, "key": "` + token + `"}`,
			`data: {"chunk": 2, "safe": "no-secret"}`,
			`data: {"chunk": 3, "key": "` + token + `"}`,
			`data: {"chunk": 4, "safe": "also-clean"}`,
			`data: [DONE]`,
		}
		for _, evt := range events {
			_, _ = w.Write([]byte(evt + "\n\n"))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &multiRedactAuth{header: "Authorization", value: "Bearer " + token, rawToken: token},
		Access:     access,
	})

	req := httptest.NewRequest("GET", "/api/stream", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	body := rec.Body.String()
	assert.NotContains(t, body, token)
	assert.Equal(t, 2, strings.Count(body, "[REDACTED]"), "two events had tokens")
	assert.Contains(t, body, "no-secret")
	assert.Contains(t, body, "also-clean")
	assert.Contains(t, body, "[DONE]")
}

func TestIntegration_SSE_MCPToolsListFiltering(t *testing.T) {
	toolsResp := "event: message\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events","description":"Get events"},` +
		`{"name":"delete_event","description":"Delete event"},` +
		`{"name":"list_calendars","description":"List calendars"}` +
		`]}}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toolsResp))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp/endpoint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)

	// The response should have delete_event filtered out.
	respBody := rec.Body.String()
	assert.Contains(t, respBody, "get_events")
	assert.Contains(t, respBody, "list_calendars")
	assert.NotContains(t, respBody, "delete_event")
}

func TestIntegration_SSE_MCPToolsListFiltering_CRLF(t *testing.T) {
	toolsResp := "event: message\r\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events","description":"Get events"},` +
		`{"name":"delete_event","description":"Delete event"},` +
		`{"name":"list_calendars","description":"List calendars"}` +
		`]}}` + "\r\n\r\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toolsResp))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp/endpoint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-crlf")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.Contains(t, respBody, "get_events")
	assert.Contains(t, respBody, "list_calendars")
	assert.NotContains(t, respBody, "delete_event", "delete_event should be filtered out")
}

func TestIntegration_SSE_MCPToolsListFiltering_ServerKeepsOpen(t *testing.T) {
	toolsResp := "event: message\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events","description":"Get events"},` +
		`{"name":"delete_event","description":"Delete event"},` +
		`{"name":"list_calendars","description":"List calendars"}` +
		`]}}` + "\n\n"

	var wg sync.WaitGroup
	wg.Add(1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte(toolsResp))
			f.Flush()
			// Keep connection open (simulating MCP SSE stream)
			wg.Wait()
		}
	}))
	defer func() {
		wg.Done()
		upstream.Close()
	}()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/mcp",
		Upstream:    upURL,
		Auth:        &noopAuth{},
		Access:      access,
		MCPRules:    mcpRules,
		IdleTimeout: 2 * time.Second,
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

	// Use a real HTTP server to get proper streaming behavior.
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		router.ServeHTTP(w, r)
	}))
	defer proxyServer.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	ctx := airlocklog.WithCorrelationID(context.Background(), "test-keepopen")
	httpReq, _ := http.NewRequestWithContext(ctx, "POST", proxyServer.URL+"/mcp/endpoint",
		bytes.NewBufferString(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(respBody), "get_events")
	assert.Contains(t, string(respBody), "list_calendars")
	assert.NotContains(t, string(respBody), "delete_event", "delete_event should be filtered out")
}

func TestIntegration_SSE_MCPToolsListFiltering_JSONWithSSEContentType(t *testing.T) {
	// Some MCP servers send JSON without SSE framing but with SSE content-type.
	toolsResp := `{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events","description":"Get events"},` +
		`{"name":"delete_event","description":"Delete event"},` +
		`{"name":"list_calendars","description":"List calendars"}` +
		`]}}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toolsResp))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp/endpoint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-json-sse-ct")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.Contains(t, respBody, "get_events")
	assert.Contains(t, respBody, "list_calendars")
	assert.NotContains(t, respBody, "delete_event", "delete_event should be filtered out")
}

func TestIntegration_SSE_MCPToolsListFiltering_MultipleEvents(t *testing.T) {
	toolsResp := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\n" +
		"event: message\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events","description":"Get events"},` +
		`{"name":"delete_event","description":"Delete event"},` +
		`{"name":"list_calendars","description":"List calendars"}` +
		`]}}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toolsResp))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp/endpoint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-multi")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.Contains(t, respBody, "get_events")
	assert.Contains(t, respBody, "list_calendars")
	assert.NotContains(t, respBody, "delete_event", "delete_event should be filtered out")
	// Notification event should pass through unchanged.
	assert.Contains(t, respBody, "notifications/initialized")
}

// =============================================================================
// SSE Transport: tools/list response on GET stream (no mcpInfo context)
// =============================================================================

func TestIntegration_SSETransport_ToolsListFilteredOnGETStream(t *testing.T) {
	// Simulates the SSE transport pattern where:
	//   - GET establishes a long-lived SSE stream
	//   - tools/list response arrives on the GET stream (no mcpInfo context)
	// The fallback path in ModifyResponse should still filter tools.
	toolsResp := "event: message\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"channels_list","description":"List channels"},` +
		`{"name":"usergroups_create","description":"Create user group"},` +
		`{"name":"usergroups_update","description":"Update user group"},` +
		`{"name":"chat_postMessage","description":"Post a message"}` +
		`]}}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte(toolsResp))
			f.Flush()
		}
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"channels_list", "chat_postMessage"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/mcp",
		Upstream:    upURL,
		Auth:        &noopAuth{},
		Access:      access,
		MCPRules:    mcpRules,
		IdleTimeout: 2 * time.Second,
	})

	// GET request — no JSON body, so no mcpInfo is set in context.
	// This simulates the SSE transport's long-lived event stream.
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		router.ServeHTTP(w, r)
	}))
	defer proxyServer.Close()

	ctx := airlocklog.WithCorrelationID(context.Background(), "sse-transport-test")
	httpReq, _ := http.NewRequestWithContext(ctx, "GET", proxyServer.URL+"/mcp/sse", nil)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	body := string(respBody)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "channels_list")
	assert.Contains(t, body, "chat_postMessage")
	assert.NotContains(t, body, "usergroups_create", "usergroups_create should be filtered out")
	assert.NotContains(t, body, "usergroups_update", "usergroups_update should be filtered out")
}

func TestIntegration_SSETransport_NonToolEventsPassThrough(t *testing.T) {
	// Verify that non-tools/list events pass through unchanged on the
	// SSE transport fallback path.
	sseData := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\n" +
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"status\":\"ok\"}}\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sseData))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"channels_list"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	// GET request — no mcpInfo, triggers SSE fallback.
	req := httptest.NewRequest("GET", "/mcp/sse", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-passthrough")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	body := rec.Body.String()
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, body, "notifications/initialized")
	assert.Contains(t, body, `"status":"ok"`)
}

func TestIntegration_SSETransport_NoFilterWithoutToolRules(t *testing.T) {
	// When MCPRules exists but has no tool rules (pass-through policy),
	// the SSE fallback should NOT wrap the body.
	toolsResp := "event: message\ndata: " +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"any_tool","description":"Some tool"}` +
		`]}}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toolsResp))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	// Empty MCPToolPolicy — no allow/deny lists.
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	req := httptest.NewRequest("GET", "/mcp/sse", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-no-rules")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	body := rec.Body.String()
	assert.Equal(t, http.StatusOK, rec.Code)
	// Tool should pass through unfiltered.
	assert.Contains(t, body, "any_tool")
}

// =============================================================================
// Full Pipeline: Correlation → Access → Rate Limit → Auth → MCP → Proxy → Redact
// =============================================================================

func TestIntegration_FullPipeline_MCPAllowedTool(t *testing.T) {
	token := "sk-mcp-secret-key"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth was injected
		assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
		// Verify agent ID header
		assert.Equal(t, "test-agent", r.Header.Get("X-Agent-Id"))
		// Verify correlation ID
		assert.NotEmpty(t, r.Header.Get("X-Correlation-Id"))
		// Verify extra headers
		assert.Equal(t, "custom-value", r.Header.Get("X-Custom"))

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "mcp-server/1.0")
		w.WriteHeader(http.StatusOK)
		// Response leaks the token
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"key":"` + token + `"}}`))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:           "/mcp",
		StripPrefix:          "/mcp",
		Upstream:             upURL,
		Auth:                 &multiRedactAuth{header: "Authorization", value: "Bearer " + token, rawToken: token},
		Access:               access,
		Limiter:              rate.NewLimiter(100, 200),
		StripResponseHeaders: []string{"Server"},
		StripAgentAuth:       true,
		MCPRules:             mcpRules,
		ExtraHeaders:         map[string]string{"X-Custom": "custom-value"},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp/endpoint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fake-agent-token")
	ctx := airlocklog.WithCorrelationID(req.Context(), "pipeline-test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)

	// Token redacted from body
	respBody := rec.Body.String()
	assert.NotContains(t, respBody, token)
	assert.Contains(t, respBody, "[REDACTED]")

	// Server header stripped
	assert.Empty(t, rec.Header().Get("Server"))
}

func TestIntegration_FullPipeline_MCPDeniedTool(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached for denied tool")
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"delete_everything"}}`
	req := httptest.NewRequest("POST", "/mcp/endpoint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusForbidden, rec.Code)

	var resp jsonRPCErrorResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, "42", string(resp.ID))
	assert.Equal(t, -32600, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "delete_everything")
}

func TestIntegration_FullPipeline_AccessBlocked(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "DENY", Method: "DELETE", Path: "/**"},
		{Action: "ALLOW", Method: "POST", Path: "/v1/chat/completions"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/openai",
		StripPrefix: "/openai",
		Upstream:    upURL,
		Auth:        &noopAuth{},
		Access:      access,
	})

	ctx := airlocklog.WithCorrelationID(context.Background(), "test")

	// DELETE should be denied by first rule
	req := httptest.NewRequest("DELETE", "/openai/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// GET should be denied by implicit deny (no matching allow rule)
	req2 := httptest.NewRequest("GET", "/openai/v1/models", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2.WithContext(ctx))
	assert.Equal(t, http.StatusForbidden, rec2.Code)

	// Blocked requests should not reach upstream
	assert.Equal(t, int64(0), upstreamCalls.Load())

	// POST to allowed path should succeed
	req3 := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3.WithContext(ctx))
	assert.Equal(t, http.StatusOK, rec3.Code)
	assert.Equal(t, int64(1), upstreamCalls.Load())
}

// =============================================================================
// MCP tools/list Filtering Integration (end-to-end through router)
// =============================================================================

func TestIntegration_MCPToolsListFiltering(t *testing.T) {
	toolsResp := `{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"get_events","description":"Get events","inputSchema":{"type":"object"}},` +
		`{"name":"delete_event","description":"Delete event"},` +
		`{"name":"list_calendars","description":"List calendars"},` +
		`{"name":"send_message","description":"Send message"}` +
		`]}}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toolsResp))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		MCPRules:   mcpRules,
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp/endpoint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resp["result"], &result))
	var tools []map[string]interface{}
	require.NoError(t, json.Unmarshal(result["tools"], &tools))

	// Only allowed tools should be in the response
	assert.Len(t, tools, 2)
	toolNames := make([]string, len(tools))
	for i, tool := range tools {
		toolNames[i] = tool["name"].(string)
	}
	assert.Contains(t, toolNames, "get_events")
	assert.Contains(t, toolNames, "list_calendars")
	assert.NotContains(t, toolNames, "delete_event")
	assert.NotContains(t, toolNames, "send_message")
}

// =============================================================================
// Upstream Error Handling
// =============================================================================

func TestIntegration_UpstreamTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		Timeout:    50 * time.Millisecond,
	})

	req := httptest.NewRequest("GET", "/api/slow", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
}

func TestIntegration_UpstreamDown(t *testing.T) {
	// Create a server and immediately close it
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	upURL, _ := url.Parse(upstream.URL)
	upstream.Close() // Close immediately

	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

// =============================================================================
// Header Injection Protection
// =============================================================================

func TestIntegration_AgentIDHeader_AlwaysInjected(t *testing.T) {
	var receivedAgentID string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAgentID = r.Header.Get("X-Agent-Id")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "my-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{AgentID: "my-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
	})

	// Even if the agent tries to set its own agent ID, the router should override
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-Agent-Id", "fake-agent")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, "my-agent", receivedAgentID)
}

func TestIntegration_CorrelationID_AlwaysInjected(t *testing.T) {
	var receivedCorrID string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCorrID = r.Header.Get("X-Correlation-Id")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "unique-corr-id-123")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, "unique-corr-id-123", receivedCorrID)
}

// =============================================================================
// Large Request/Response Bodies
// =============================================================================

func TestIntegration_LargeRequestBody(t *testing.T) {
	var receivedSize int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedSize = len(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
	})

	// 1MB request body
	bigBody := strings.Repeat("A", 1024*1024)
	req := httptest.NewRequest("POST", "/api/upload", strings.NewReader(bigBody))
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1024*1024, receivedSize)
}

func TestIntegration_LargeResponseWithRedaction(t *testing.T) {
	token := "sk-secret-in-large-response"
	// 500KB response with token in the middle
	prefix := strings.Repeat("A", 250*1024)
	suffix := strings.Repeat("B", 250*1024)
	responseBody := prefix + token + suffix

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &multiRedactAuth{header: "Authorization", value: "Bearer " + token, rawToken: token},
		Access:     access,
	})

	req := httptest.NewRequest("GET", "/api/large", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.NotContains(t, body, token)
	assert.Contains(t, body, "[REDACTED]")
}

// =============================================================================
// StripPrefix Edge Cases
// =============================================================================

func TestIntegration_StripPrefix_RootPath(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/openai",
		StripPrefix: "/openai",
		Upstream:    upURL,
		Auth:        &noopAuth{},
		Access:      access,
	})

	// Request to just the prefix — should map to /
	req := httptest.NewRequest("GET", "/openai", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "/", receivedPath)
}

// =============================================================================
// ExtraHeaders Integration
// =============================================================================

func TestIntegration_ExtraHeaders_Injected(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, _ := url.Parse(upstream.URL)
	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	access, _ := NewAccessPolicy(nil, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/api",
		Upstream:   upURL,
		Auth:       &noopAuth{},
		Access:     access,
		ExtraHeaders: map[string]string{
			"anthropic-beta":    "oauth-2025-04-20",
			"anthropic-version": "2023-06-01",
			"X-Custom":          "value",
		},
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, "oauth-2025-04-20", receivedHeaders.Get("anthropic-beta"))
	assert.Equal(t, "2023-06-01", receivedHeaders.Get("anthropic-version"))
	assert.Equal(t, "value", receivedHeaders.Get("X-Custom"))
}

// =============================================================================
// path_regex end-to-end (mirrors the spec's curl reproducer)
// =============================================================================

// Reproduces the Maya use case: PUT to AI-<digits> issues reaches the upstream;
// PUT to BACK-<digits> is denied at the gateway with 403.
func TestIntegration_PathRegex_JiraIssueWriteRestriction(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream:" + r.Method + ":" + r.URL.Path))
	}))
	defer upstream.Close()

	upURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/rest/api/3/myself"},
		{Action: "ALLOW", Method: "PUT", PathRegex: `/rest/api/3/issue/AI-\d+`},
		{Action: "ALLOW", Method: "GET", PathRegex: `/rest/api/3/issue/AI-\d+`},
		{Action: "ALLOW", Method: "POST", PathRegex: `/rest/api/3/issue/AI-\d+/comment`},
		{Action: "DENY", Method: "ALL", Path: "/**"},
	}, false)
	require.NoError(t, err)

	logger := airlocklog.NewLogger(devNull{}, "test", "test-agent")
	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/jira",
		StripPrefix: "/jira",
		Upstream:    upURL,
		Auth:        &noopAuth{},
		Access:      access,
	})

	ctx := airlocklog.WithCorrelationID(context.Background(), "regex-test")

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantUpHit  bool
	}{
		{"PUT AI-1234 reaches upstream", "PUT", "/jira/rest/api/3/issue/AI-1234", http.StatusOK, true},
		{"PUT BACK-1234 denied at gateway", "PUT", "/jira/rest/api/3/issue/BACK-1234", http.StatusForbidden, false},
		{"GET AI-9 reaches upstream", "GET", "/jira/rest/api/3/issue/AI-9", http.StatusOK, true},
		{"GET BACK-9 denied at gateway", "GET", "/jira/rest/api/3/issue/BACK-9", http.StatusForbidden, false},
		{"POST AI-1/comment reaches upstream", "POST", "/jira/rest/api/3/issue/AI-1/comment", http.StatusOK, true},
		{"DELETE AI-1 denied (no rule matches verb)", "DELETE", "/jira/rest/api/3/issue/AI-1", http.StatusForbidden, false},
		{"GET myself reaches upstream (glob rule)", "GET", "/jira/rest/api/3/myself", http.StatusOK, true},
		{"GET unrelated denied", "GET", "/jira/rest/api/3/project", http.StatusForbidden, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := hits.Load()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req.WithContext(ctx))
			assert.Equal(t, tc.wantStatus, rec.Code)
			gotUpHit := hits.Load() > before
			assert.Equal(t, tc.wantUpHit, gotUpHit, "upstream hit expectation")
		})
	}
}
