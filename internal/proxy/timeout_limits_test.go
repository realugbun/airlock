package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/realugbun/airlock/internal/auth"
	"github.com/realugbun/airlock/internal/middleware"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Over a real connection, a body that stalls is cut off at the route
// timeout, through the production middleware chain.
func TestRouter_RouteTimeoutCutsOffStalledBody(t *testing.T) {
	var hits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "POST", Path: "/"}}, false)
	require.NoError(t, err)
	logger := airlocklog.NewLogger(io.Discard, "test", "")
	router := NewRouter(RouterConfig{Logger: logger})
	router.AddRoute(&Route{
		PathPrefix: "/mcp", StripPrefix: "/mcp", Upstream: upstreamURL,
		Auth: auth.NewNoneAuth(), Access: access, MCPRules: allowlistPolicy(t),
		Timeout: 200 * time.Millisecond,
	})
	var handler http.Handler = router
	handler = middleware.RequestLogger(logger)(handler)
	handler = middleware.Correlation(handler)
	gw := httptest.NewServer(handler)
	defer gw.Close()

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	go func() { _, _ = pw.Write([]byte(`{"jsonrpc":"2.0",`)) }() // then stall

	req, err := http.NewRequest(http.MethodPost, gw.URL+"/mcp", pr)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
	assert.Less(t, elapsed, 2*time.Second)
	assert.Zero(t, hits)
}

func toolsListRouter(t *testing.T, upstream *httptest.Server) *httptest.Server {
	t.Helper()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "POST", Path: "/"}}, false)
	require.NoError(t, err)
	router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "test", "")})
	router.AddRoute(&Route{
		PathPrefix: "/mcp", StripPrefix: "/mcp", Upstream: upstreamURL,
		Auth: auth.NewNoneAuth(), Access: access, MCPRules: allowlistPolicy(t),
		Timeout: 30 * time.Second,
	})
	gw := httptest.NewServer(router)
	t.Cleanup(gw.Close)
	return gw
}

func postToolsList(t *testing.T, gw *httptest.Server) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestRouter_ToolsListResponseCap(t *testing.T) {
	t.Run("oversized content-length", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(maxMCPResponseSize+1))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0"`))
		}))
		defer upstream.Close()
		resp := postToolsList(t, toolsListRouter(t, upstream))
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})

	t.Run("endless stream without content-length", func(t *testing.T) {
		stop := make(chan struct{})
		var written int
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			chunk := bytes.Repeat([]byte(" "), 64*1024)
			for {
				select {
				case <-stop:
					return
				default:
				}
				n, err := w.Write(chunk)
				written += n
				if err != nil || written > 4*maxMCPResponseSize {
					return
				}
			}
		}))
		defer upstream.Close()
		defer close(stop)

		start := time.Now()
		resp := postToolsList(t, toolsListRouter(t, upstream))
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
		assert.Less(t, time.Since(start), 10*time.Second)
	})

	t.Run("normal response is filtered", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read"},{"name":"delete_all"}]}}`))
		}))
		defer upstream.Close()
		resp := postToolsList(t, toolsListRouter(t, upstream))
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, string(body), `"read"`)
		assert.NotContains(t, string(body), "delete_all")
	})
}
