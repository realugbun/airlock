package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/realugbun/airlock/internal/auth"
	"github.com/realugbun/airlock/internal/middleware"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

type MockAuthProvider struct {
	mock.Mock
}

func (m *MockAuthProvider) AddAuth(ctx context.Context, req *http.Request) ([]string, error) {
	args := m.Called(ctx, req)
	var redact []string
	if v := args.Get(0); v != nil {
		redact = v.([]string)
	}
	return redact, args.Error(1)
}

func newTestRouter(t *testing.T, upstreamURL string, mockAuth auth.AuthProvider, agentID string) *Router {
	t.Helper()
	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", agentID)

	upstream, err := url.Parse(upstreamURL)
	require.NoError(t, err)

	router := NewRouter(RouterConfig{
		AgentID: agentID,
		Logger:  logger,
	})

	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/v1/chat/completions"},
		{Action: "ALLOW", Method: "ALL", Path: "/v1/embeddings"},
	}, false)
	require.NoError(t, err)

	router.AddRoute(&Route{
		PathPrefix:  "/openai",
		StripPrefix: "/openai",
		Upstream:    upstream,
		Auth:        mockAuth,
		Access:      access,
		Limiter:     rate.NewLimiter(100, 200),
	})

	return router
}

type devNull struct{ buf [0]byte }

func (d devNull) Write(p []byte) (int, error) { return len(p), nil }

func TestRouter_HealthCheck(t *testing.T) {
	mockAuth := new(MockAuthProvider)
	router := newTestRouter(t, "http://unused", mockAuth, "test-agent")

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestRouter_NotFound(t *testing.T) {
	mockAuth := new(MockAuthProvider)
	router := newTestRouter(t, "http://unused", mockAuth, "test-agent")

	req := httptest.NewRequest("GET", "/unknown/path", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRouter_BlocksDisallowedPath(t *testing.T) {
	mockAuth := new(MockAuthProvider)
	router := newTestRouter(t, "http://unused", mockAuth, "test-agent")

	req := httptest.NewRequest("GET", "/openai/v1/models", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	// Wrap with request log context
	rl := &middleware.RequestLog{}
	ctx = context.WithValue(req.Context(), requestLogKeyForTest{}, rl)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	mockAuth.AssertNotCalled(t, "AddAuth")
}

type requestLogKeyForTest struct{}

func TestRouter_ProxiesRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.NotEmpty(t, r.Header.Get("X-Correlation-Id"))
		assert.Equal(t, "test-agent", r.Header.Get("X-Agent-Id"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"test-token"}, nil)

	router := newTestRouter(t, upstream.URL, mockAuth, "test-agent")

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr-id")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockAuth.AssertExpectations(t)
}

func TestRouter_RedactsResponseBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the Authorization header back in the response body (like httpbin /headers).
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Authorization": "` + r.Header.Get("Authorization") + `"}`))
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		req := args.Get(1).(*http.Request)
		req.Header.Set("Authorization", "Bearer sk-secret-token")
	}).Return([]string{"sk-secret-token", "Bearer sk-secret-token"}, nil)

	router := newTestRouter(t, upstream.URL, mockAuth, "test-agent")

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.NotContains(t, body, "sk-secret-token")
	assert.Contains(t, body, "[REDACTED]")
}

func TestRouter_RedactsResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the credential in a response header.
		w.Header().Set("X-Debug-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		req := args.Get(1).(*http.Request)
		req.Header.Set("Authorization", "Bearer sk-secret-token")
	}).Return([]string{"sk-secret-token", "Bearer sk-secret-token"}, nil)

	router := newTestRouter(t, upstream.URL, mockAuth, "test-agent")

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Header().Get("X-Debug-Auth"), "sk-secret-token")
	assert.Contains(t, rec.Header().Get("X-Debug-Auth"), "[REDACTED]")
}

func TestRouter_StripsResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"test-token"}, nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstreamURL, _ := url.Parse(upstream.URL)
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/v1/chat/completions"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:           "/openai",
		StripPrefix:          "/openai",
		Upstream:             upstreamURL,
		Auth:                 mockAuth,
		Access:               access,
		Limiter:              rate.NewLimiter(100, 200),
		StripResponseHeaders: []string{"Server", "X-Powered-By"},
	})

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Server"))
	assert.Empty(t, rec.Header().Get("X-Powered-By"))
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestRouter_TotalTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stall longer than the timeout.
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"token"}, nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstreamURL, _ := url.Parse(upstream.URL)
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/v1/chat/completions"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/openai",
		StripPrefix: "/openai",
		Upstream:    upstreamURL,
		Auth:        mockAuth,
		Access:      access,
		Limiter:     rate.NewLimiter(100, 200),
		Timeout:     100 * time.Millisecond,
	})

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
}

func TestRouter_IdleTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Send first chunk, then stall.
		_, _ = w.Write([]byte("data: hello\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(2 * time.Second)
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"token"}, nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstreamURL, _ := url.Parse(upstream.URL)
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/v1/chat/completions"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/openai",
		StripPrefix: "/openai",
		Upstream:    upstreamURL,
		Auth:        mockAuth,
		Access:      access,
		Limiter:     rate.NewLimiter(100, 200),
		IdleTimeout: 100 * time.Millisecond,
		Timeout:     0, // no total timeout
	})

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Response started with 200 (headers sent before stall).
	// Body should contain at least some data but be truncated
	// (the idle timeout may fire mid-chunk depending on timing).
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "data:")
}

func TestRouter_StripAgentAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the agent's fake headers were stripped and only Airlock's remain.
		assert.Equal(t, "Bearer real-token", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("x-api-key"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		req := args.Get(1).(*http.Request)
		req.Header.Set("Authorization", "Bearer real-token")
	}).Return([]string{"real-token"}, nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstreamURL, _ := url.Parse(upstream.URL)
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/v1/messages"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:     "/anthropic",
		StripPrefix:    "/anthropic",
		Upstream:       upstreamURL,
		Auth:           mockAuth,
		Access:         access,
		Limiter:        rate.NewLimiter(100, 200),
		StripAgentAuth: true,
	})

	req := httptest.NewRequest("POST", "/anthropic/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer fake-dummy-token")
	req.Header.Set("x-api-key", "fake-api-key")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockAuth.AssertExpectations(t)
}

func TestRouter_ExtraHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "oauth-2025-04-20", r.Header.Get("anthropic-beta"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"token"}, nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstreamURL, _ := url.Parse(upstream.URL)
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/v1/messages"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:  "/anthropic",
		StripPrefix: "/anthropic",
		Upstream:    upstreamURL,
		Auth:        mockAuth,
		Access:      access,
		Limiter:     rate.NewLimiter(100, 200),
		ExtraHeaders: map[string]string{
			"anthropic-beta":    "oauth-2025-04-20",
			"anthropic-version": "2023-06-01",
		},
	})

	req := httptest.NewRequest("POST", "/anthropic/v1/messages", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- MCP Tool Filtering Integration Tests ---

func newMCPTestRouter(t *testing.T, upstreamURL string, mockAuth auth.AuthProvider, mcpRules *MCPToolPolicy) *Router {
	t.Helper()
	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstream, err := url.Parse(upstreamURL)
	require.NoError(t, err)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})

	// Allow all paths so access rules don't interfere with MCP tests.
	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	require.NoError(t, err)

	router.AddRoute(&Route{
		PathPrefix:  "/mcp",
		StripPrefix: "/mcp",
		Upstream:    upstream,
		Auth:        mockAuth,
		Access:      access,
		Limiter:     rate.NewLimiter(100, 200),
		MCPRules:    mcpRules,
	})

	return router
}

func TestRouter_MCPToolAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"token"}, nil)

	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events", "list_calendars"},
	})

	router := newMCPTestRouter(t, upstream.URL, mockAuth, mcpRules)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockAuth.AssertExpectations(t)
}

func TestRouter_MCPToolDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for denied tool")
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)

	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"},
	})

	router := newMCPTestRouter(t, upstream.URL, mockAuth, mcpRules)

	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_event","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	// Verify JSON-RPC error response.
	var resp jsonRPCErrorResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, "5", string(resp.ID))
	assert.Equal(t, -32600, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "delete_event")

	// Auth should not have been called.
	mockAuth.AssertNotCalled(t, "AddAuth")
}

func TestRouter_MCPNonToolPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"token"}, nil)

	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		AllowedTools: []string{"get_events"}, // strict allowlist
	})

	router := newMCPTestRouter(t, upstream.URL, mockAuth, mcpRules)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/mcp/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockAuth.AssertExpectations(t)
}

func TestRouter_MCPDenyList(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"token"}, nil)

	mcpRules, _ := NewMCPToolPolicy(&MCPToolPolicyConfig{
		DeniedTools: []string{"delete_event", "send_message"},
	})

	router := newMCPTestRouter(t, upstream.URL, mockAuth, mcpRules)

	// Allowed tool (not in deny list).
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events"}}`
	req := httptest.NewRequest("POST", "/mcp/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, upstreamCalled)

	// Denied tool.
	upstreamCalled = false
	body = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_event"}}`
	req = httptest.NewRequest("POST", "/mcp/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx = airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec = httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, upstreamCalled)
}

func TestRouter_MCPNoRulesPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string{"token"}, nil)

	// nil MCPRules — no MCP filtering.
	router := newMCPTestRouter(t, upstream.URL, mockAuth, nil)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"anything_goes"}}`
	req := httptest.NewRequest("POST", "/mcp/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockAuth.AssertExpectations(t)
}
