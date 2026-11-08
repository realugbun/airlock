package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/realugbun/airlock/internal/auth"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A credential containing '[' or ']' can combine with the bytes next to a
// "[REDACTED]" replacement and spell the credential again, so it cannot be
// redacted from a response.
func TestRedactionSafe_BracketsRefused(t *testing.T) {
	safe := [][]string{
		{"sk-abc"},
		{"sk-abc", "Bearer sk-abc"},
		{""},
		nil,
		{"REDACTED"},
		{"token-with-{braces}"},
	}
	for _, secrets := range safe {
		assert.True(t, redactionSafe(secrets), "%q should be redactable", secrets)
	}

	unsafe := [][]string{
		{"]Z!"},
		{"sk-[abc"},
		{"sk-abc]"},
		{"sk-abc", "Bearer sk-[abc"},
		{"["},
	}
	for _, secrets := range unsafe {
		assert.False(t, redactionSafe(secrets), "%q must not be redactable", secrets)
	}
}

// With a bracketed credential the redacted body can contain the credential:
// secrets {"XY", "]Z!"} turn the body "XYZ!" into "[REDACTED]Z!", which
// contains "]Z!". This is why such a credential is refused at the router.
func TestRedact_PlaceholderCanRecreateBracketedSecret(t *testing.T) {
	secrets := []string{"XY", "]Z!"}
	out := oneShotRedact(secrets, []byte("XYZ!"))
	require.Equal(t, "[REDACTED]Z!", string(out))
	require.Contains(t, string(out), "]Z!", "the placeholder re-formed the secret")
	require.False(t, redactionSafe(secrets))
}

// bracketAuth injects a credential that contains a bracket, like a static
// token whose secret value happens to include one.
type bracketAuth struct{ token string }

func (a *bracketAuth) AddAuth(_ context.Context, r *http.Request) ([]string, error) {
	r.Header.Set("Authorization", "Bearer "+a.token)
	return []string{a.token, "Bearer " + a.token}, nil
}

func newRedactRouterWithLog(t *testing.T, upstream *httptest.Server, provider auth.AuthProvider, logs io.Writer) *Router {
	t.Helper()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "ALL", Path: "/**"},
	}, false)
	require.NoError(t, err)
	router := NewRouter(RouterConfig{
		AgentID: "test-agent",
		Logger:  airlocklog.NewLogger(logs, "redaction", "test-agent"),
	})
	router.AddRoute(&Route{
		PathPrefix:  "/u",
		StripPrefix: "/u",
		Upstream:    upstreamURL,
		Auth:        provider,
		Access:      access,
	})
	return router
}

func TestRouter_BracketedCredentialRefusedBeforeUpstream(t *testing.T) {
	const token = "sk-live-]-abc"

	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte("should never be reached"))
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	gw := httptest.NewServer(newRedactRouterWithLog(t, upstream, &bracketAuth{token: token}, &logs))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/u/x")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.GreaterOrEqual(t, resp.StatusCode, 500, "must fail closed with a 5xx")
	assert.Less(t, resp.StatusCode, 600)
	assert.Equal(t, int64(0), upstreamHits.Load(), "upstream must not be contacted")
	assert.NotContains(t, string(body), token)

	logged := logs.String()
	assert.Contains(t, logged, "credential cannot be redacted")
	assert.Contains(t, logged, "/u", "the log must name the route")
	assert.NotContains(t, logged, token, "the log must not contain the credential")
	assert.NotContains(t, logged, "sk-live", "the log must not contain the credential")
}

// An opening bracket in only the injected header value (for example from the
// auth prefix) is refused too.
func TestRouter_BracketedPrefixRefused(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	provider := prefixOnlyBracketAuth{}
	gw := httptest.NewServer(newRedactRouterWithLog(t, upstream, provider, &logs))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/u/x")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, int64(0), upstreamHits.Load())
}

type prefixOnlyBracketAuth struct{}

func (prefixOnlyBracketAuth) AddAuth(_ context.Context, r *http.Request) ([]string, error) {
	r.Header.Set("Authorization", "[Token] sk-plain")
	return []string{"sk-plain", "[Token] sk-plain"}, nil
}

// A credential with no bracket is unaffected: the request is proxied and the
// response is redacted as before.
func TestRouter_OrdinaryCredentialStillProxied(t *testing.T) {
	const token = "sk-ordinary-token"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("echo " + r.Header.Get("Authorization")))
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	gw := httptest.NewServer(newRedactRouterWithLog(t, upstream, &bracketAuth{token: token}, &logs))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/u/x")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "echo [REDACTED]", string(body))
	assert.NotContains(t, string(body), token)
}
