package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/realugbun/airlock/internal/auth"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/require"
)

// Reproductions from a security review of v0.2.1. Each asserts the security
// invariant and failed before the corresponding fix.

func TestRedTeam_MCPRejectsOversizedDeniedToolCall(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"safe_read"}})
	require.NoError(t, err)
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call jsonRPCRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&call))
		upstreamCalled = call.Method == "tools/call" && call.Params != nil && call.Params.Name == "delete_everything"
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "POST", Path: "/"}}, false)
	require.NoError(t, err)
	router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "redteam", "")})
	router.AddRoute(&Route{
		PathPrefix: "/mcp", StripPrefix: "/mcp", Upstream: upstreamURL,
		Auth: auth.NewNoneAuth(), Access: access, MCPRules: p,
	})
	gateway := httptest.NewServer(router)
	defer gateway.Close()

	prefix := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything"}}`)
	body := append(prefix, bytes.Repeat([]byte(" "), maxMCPBodySize+2-len(prefix))...)
	// Hide the concrete bytes.Reader type so net/http uses chunked transfer.
	req, err := http.NewRequest(http.MethodPost, gateway.URL+"/mcp", struct{ io.Reader }{bytes.NewReader(body)})
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "oversized calls must fail closed")
	require.False(t, upstreamCalled, "a denied tool must not execute upstream")
}

func TestRedTeam_MCPContentTypeIsParsedCaseInsensitively(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"safe_read"}})
	require.NoError(t, err)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "Application/JSON")

	result, err := p.CheckRequest(req)
	require.NoError(t, err)
	require.True(t, result.Denied, "JSON media types are case-insensitive and must not bypass MCP policy")
}

func TestRedTeam_SSERedactionSurvivesSafetyFlushBoundary(t *testing.T) {
	const secret = "secret-token"
	// The 1 MiB safety flush currently splits the credential across two calls
	// to the stateless transform.
	prefix := bytes.Repeat([]byte("A"), sseMaxEventBuf-3)
	data := append(prefix, []byte(secret)...)
	data = append(data, []byte("\n\n")...)

	r := newSSERedactingReader(io.NopCloser(bytes.NewReader(data)), []string{secret})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.False(t, bytes.Contains(out, []byte(secret)),
		"the injected credential must never cross an SSE flush unredacted")
}

func TestRedTeam_ResponseTrailerCredentialIsRedacted(t *testing.T) {
	const secret = "secret-token-in-trailer"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Debug-Auth")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		w.Header().Set("X-Debug-Auth", secret)
	}))
	defer upstream.Close()

	router := newRedactRouter(t, upstream, &redactAuth{secret: secret})
	gateway := httptest.NewServer(router)
	defer gateway.Close()

	resp, err := http.Get(gateway.URL + "/u/thing")
	require.NoError(t, err)
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.NotContains(t, resp.Trailer.Get("X-Debug-Auth"), secret,
		"response trailers are part of the response and must be redacted")
}

func TestRedTeam_InformationalResponseCredentialIsRedacted(t *testing.T) {
	const secret = "secret-token-in-early-hints"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Debug-Auth", secret)
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("X-Debug-Auth")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	router := newRedactRouter(t, upstream, &redactAuth{secret: secret})
	gateway := httptest.NewServer(router)
	defer gateway.Close()

	var earlyHeader textproto.MIMEHeader
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints {
			earlyHeader = header
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace),
		http.MethodGet, gateway.URL+"/u/thing", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	require.NotContains(t, earlyHeader.Get("X-Debug-Auth"), secret,
		"1xx response headers must pass through credential redaction")
}

type injectedHeaderAuth struct{}

func (*injectedHeaderAuth) AddAuth(_ context.Context, r *http.Request) ([]string, error) {
	r.Header.Set("Authorization", "Bearer real-secret")
	return []string{"real-secret", "Bearer real-secret"}, nil
}

func TestRedTeam_AgentCannotNominateInjectedHeadersAsHopByHop(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "GET", Path: "/"}}, false)
	require.NoError(t, err)
	router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "redteam", "")})
	router.AddRoute(&Route{
		PathPrefix: "/u", StripPrefix: "/u", Upstream: upstreamURL,
		Auth: &injectedHeaderAuth{}, Access: access,
		ExtraHeaders: map[string]string{"X-Security-Scope": "restricted"},
	})

	req := httptest.NewRequest(http.MethodGet, "/u", nil)
	req.Header.Set("Connection", "Authorization, X-Security-Scope")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(airlocklog.WithCorrelationID(context.Background(), "redteam")))
	got := <-seen

	require.Equal(t, "Bearer real-secret", got.Get("Authorization"),
		"agent-controlled Connection tokens must not delete injected authentication")
	require.Equal(t, "restricted", got.Get("X-Security-Scope"),
		"agent-controlled Connection tokens must not delete configured security headers")
}

func TestRedTeam_DotSegmentCannotEscapeAllowedPath(t *testing.T) {
	var normalizedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		normalizedPath = path.Clean(r.URL.Path) // common framework/proxy behavior
		if normalizedPath == "/admin" {
			w.WriteHeader(http.StatusCreated) // stand-in for a forbidden operation
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "POST", Path: "/allowed/**"}}, false)
	require.NoError(t, err)
	router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "redteam", "")})
	router.AddRoute(&Route{
		PathPrefix: "/u", StripPrefix: "/u", Upstream: upstreamURL,
		Auth: auth.NewNoneAuth(), Access: access,
	})

	req := httptest.NewRequest(http.MethodPost, "/u/allowed/../admin", nil)
	req = req.WithContext(airlocklog.WithCorrelationID(context.Background(), "redteam"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.NotEqual(t, "/admin", normalizedPath, "dot-segment traversal must be rejected before reaching upstream")
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

type delayedBody struct {
	delay time.Duration
	done  bool
}

func (b *delayedBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	time.Sleep(b.delay)
	b.done = true
	return copy(p, []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)), io.EOF
}

func (b *delayedBody) Close() error { return nil }

func TestRedTeam_RouteTimeoutCoversMCPBodyInspection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "POST", Path: "/"}}, false)
	require.NoError(t, err)
	mcp, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"safe_read"}})
	require.NoError(t, err)
	router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "redteam", "")})
	router.AddRoute(&Route{
		PathPrefix: "/mcp", StripPrefix: "/mcp", Upstream: upstreamURL,
		Auth: auth.NewNoneAuth(), Access: access, MCPRules: mcp, Timeout: 25 * time.Millisecond,
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Body = &delayedBody{delay: 150 * time.Millisecond}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(airlocklog.WithCorrelationID(context.Background(), "redteam")))
	elapsed := time.Since(start)

	require.Less(t, elapsed, 100*time.Millisecond, "route timeout must include security inspection of the request body")
}
