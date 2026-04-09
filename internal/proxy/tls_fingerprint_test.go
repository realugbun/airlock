package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	airlocklog "github.com/realugbun/airlock/pkg/log"
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUtlsClientHelloID(t *testing.T) {
	tests := []struct {
		name     string
		expected *utls.ClientHelloID
	}{
		{"chrome", &utls.ClientHelloID{Client: "Chrome", Version: "Auto", Seed: nil, Weights: nil}},
		{"firefox", &utls.ClientHelloID{Client: "Firefox", Version: "Auto", Seed: nil, Weights: nil}},
		{"random", &utls.ClientHelloID{Client: "Randomized", Version: "Randomized", Seed: nil, Weights: nil}},
		{"", nil},
		{"go", nil},
	}

	for _, tt := range tests {
		t.Run("fp="+tt.name, func(t *testing.T) {
			got := utlsClientHelloID(tt.name)
			if tt.expected == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.expected.Client, got.Client)
			}
		})
	}
}

func TestInitRouteProxy_NoFingerprint_UsesDefaultTransport(t *testing.T) {
	// A route without TLSFingerprint should use standard Go TLS (no DialTLSContext).
	upstream, _ := url.Parse("https://api.example.com")
	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "")

	route := &Route{
		PathPrefix: "/test",
		Upstream:   upstream,
	}
	initRouteProxy(route, logger)

	// The proxy should be initialized.
	assert.NotNil(t, route.proxy)
}

func TestInitRouteProxy_WithFingerprint_CreatesProxy(t *testing.T) {
	// A route with TLSFingerprint should create a working proxy and use direct proxy for HTTPS.
	for _, fp := range []string{"chrome", "firefox", "random"} {
		t.Run(fp, func(t *testing.T) {
			upstream, _ := url.Parse("https://api.example.com")
			var buf [0]byte
			logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "")

			route := &Route{
				PathPrefix:     "/test",
				Upstream:       upstream,
				TLSFingerprint: fp,
			}
			initRouteProxy(route, logger)
			assert.NotNil(t, route.proxy)
			assert.True(t, route.useDirectProxy, "HTTPS route with TLS fingerprint should use direct proxy")
			assert.NotNil(t, route.directClient, "direct client should be initialized")
		})
	}
}

func TestInitRouteProxy_WithFingerprint_HTTP_NoDirectProxy(t *testing.T) {
	// A route with TLSFingerprint on plain HTTP should NOT use direct proxy.
	upstream, _ := url.Parse("http://api.example.com")
	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "")

	route := &Route{
		PathPrefix:     "/test",
		Upstream:       upstream,
		TLSFingerprint: "chrome",
	}
	initRouteProxy(route, logger)
	assert.NotNil(t, route.proxy)
	assert.False(t, route.useDirectProxy, "HTTP route should not use direct proxy even with fingerprint")
	assert.Nil(t, route.directClient)
}

func TestTLSFingerprint_HTTPUpstream_StillWorks(t *testing.T) {
	// Even with tls_fingerprint set, plain HTTP upstreams should proxy fine
	// (the DialTLSContext only applies to TLS connections).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL) // http://127.0.0.1:PORT

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string(nil), nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "agent")

	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	require.NoError(t, err)

	router := NewRouter(RouterConfig{AgentID: "agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:     "/test",
		StripPrefix:    "/test",
		Upstream:       upstreamURL,
		Auth:           mockAuth,
		Access:         access,
		TLSFingerprint: "chrome", // set on a non-TLS upstream
	})

	req := httptest.NewRequest("GET", "/test/hello", nil)
	req = req.WithContext(context.Background())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestDirectProxy_ProxiesRequest(t *testing.T) {
	// Verify the direct proxy path (used for TLS fingerprint routes) correctly
	// proxies requests, copies headers, strips prefix, and streams responses.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "test-agent", r.Header.Get("X-Agent-Id"))
		assert.NotEmpty(t, r.Header.Get("X-Correlation-Id"))
		// Hop-by-hop headers should NOT be forwarded.
		assert.Empty(t, r.Header.Get("Connection"))
		w.Header().Set("X-Custom", "upstream-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("direct proxy response"))
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string(nil), nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstreamURL, _ := url.Parse(upstream.URL)
	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	require.NoError(t, err)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	route := &Route{
		PathPrefix:  "/openai",
		StripPrefix: "/openai",
		Upstream:    upstreamURL,
		Auth:        mockAuth,
		Access:      access,
	}
	initRouteProxy(route, logger)
	// Manually enable direct proxy to test the code path with a plain HTTP server.
	route.useDirectProxy = true
	route.directClient = &http.Client{
		Transport: route.proxy.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	router.SetRoutes([]*Route{route})

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	req.Header.Set("Connection", "keep-alive") // hop-by-hop, should be stripped
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "direct proxy response", rec.Body.String())
	assert.Equal(t, "upstream-value", rec.Header().Get("X-Custom"))
}

func TestDirectProxy_SSEStreaming(t *testing.T) {
	// Verify the direct proxy path streams SSE responses correctly.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f := w.(http.Flusher)
		_, _ = w.Write([]byte("data: hello\n\n"))
		f.Flush()
		_, _ = w.Write([]byte("data: world\n\n"))
		f.Flush()
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string(nil), nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstreamURL, _ := url.Parse(upstream.URL)
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	route := &Route{
		PathPrefix:  "/test",
		StripPrefix: "/test",
		Upstream:    upstreamURL,
		Auth:        mockAuth,
		Access:      access,
	}
	initRouteProxy(route, logger)
	route.useDirectProxy = true
	route.directClient = &http.Client{
		Transport: route.proxy.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	router.SetRoutes([]*Route{route})

	req := httptest.NewRequest("GET", "/test/stream", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "data: hello")
	assert.Contains(t, rec.Body.String(), "data: world")
}

func TestDirectProxy_RedactsCredentials(t *testing.T) {
	// Verify the direct proxy path redacts credentials from response body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key": "sk-secret-token"}`))
	}))
	defer upstream.Close()

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		req := args.Get(1).(*http.Request)
		req.Header.Set("Authorization", "Bearer sk-secret-token")
	}).Return([]string{"sk-secret-token"}, nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "test-agent")

	upstreamURL, _ := url.Parse(upstream.URL)
	access, _ := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)

	router := NewRouter(RouterConfig{AgentID: "test-agent", Logger: logger})
	route := &Route{
		PathPrefix:  "/test",
		StripPrefix: "/test",
		Upstream:    upstreamURL,
		Auth:        mockAuth,
		Access:      access,
	}
	initRouteProxy(route, logger)
	route.useDirectProxy = true
	route.directClient = &http.Client{
		Transport: route.proxy.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	router.SetRoutes([]*Route{route})

	req := httptest.NewRequest("GET", "/test/data", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "sk-secret-token")
	assert.Contains(t, rec.Body.String(), "[REDACTED]")
}

func TestTLSFingerprint_BackwardCompat_EmptyString(t *testing.T) {
	// Routes without tls_fingerprint (empty string) should still work exactly
	// as before — no uTLS, no behavioral change.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("compat"))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)

	mockAuth := new(MockAuthProvider)
	mockAuth.On("AddAuth", mock.Anything, mock.Anything).Return([]string(nil), nil)

	var buf [0]byte
	logger := airlocklog.NewLogger(devNull{buf: buf}, "test", "agent")

	access, err := NewAccessPolicy(nil, false)
	require.NoError(t, err)

	router := NewRouter(RouterConfig{AgentID: "agent", Logger: logger})
	router.AddRoute(&Route{
		PathPrefix:     "/compat",
		StripPrefix:    "/compat",
		Upstream:       upstreamURL,
		Auth:           mockAuth,
		Access:         access,
		TLSFingerprint: "", // explicitly empty
	})

	req := httptest.NewRequest("GET", "/compat/foo", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "compat", rec.Body.String())
}

