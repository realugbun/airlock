package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"testing"

	"github.com/realugbun/airlock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type prefixedRedactAuth struct{}

func (prefixedRedactAuth) AddAuth(_ context.Context, r *http.Request) ([]string, error) {
	r.Header.Set("Authorization", "Bearer sk-trailer-secret")
	return []string{"sk-trailer-secret", "Bearer sk-trailer-secret"}, nil
}

func TestRouter_TrailersAreRedacted(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Declared, X-Declared-Prefixed")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
		w.Header().Set("X-Declared", "sk-trailer-secret")
		w.Header().Set("X-Declared-Prefixed", r.Header.Get("Authorization"))
		w.Header().Set(http.TrailerPrefix+"X-Undeclared", "token=sk-trailer-secret")
		w.Header().Set(http.TrailerPrefix+"X-Harmless", "fine")
	}))
	defer upstream.Close()
	gw := httptest.NewServer(newRedactRouter(t, upstream, prefixedRedactAuth{}))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/u/x")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "body", string(body))

	require.NotEmpty(t, resp.Trailer)
	for k, vv := range resp.Trailer {
		for _, v := range vv {
			assert.NotContains(t, v, "sk-trailer-secret", "trailer %s", k)
		}
	}
	assert.Equal(t, "[REDACTED]", resp.Trailer.Get("X-Declared"))
	assert.Equal(t, "[REDACTED]", resp.Trailer.Get("X-Declared-Prefixed"))
	assert.Equal(t, "token=[REDACTED]", resp.Trailer.Get("X-Undeclared"))
	assert.Equal(t, "fine", resp.Trailer.Get("X-Harmless"))
}

func informationalUpstream(secret string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for _, code := range []int{http.StatusProcessing, http.StatusEarlyHints, 199} {
			w.Header().Set("X-Debug-Auth", secret)
			w.WriteHeader(code)
		}
		w.Header().Del("X-Debug-Auth")
		w.Header().Set("X-Final", "Bearer "+secret)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok " + secret))
	}))
}

func getWith1xxTrace(t *testing.T, url string) (*http.Response, []int, string) {
	t.Helper()
	var codes []int
	var leaked string
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		codes = append(codes, code)
		leaked += h.Get("X-Debug-Auth")
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp, codes, leaked
}

func TestRouter_InformationalResponsesSuppressedWhenRedacting(t *testing.T) {
	const secret = "sk-early-hints-secret"
	upstream := informationalUpstream(secret)
	defer upstream.Close()
	gw := httptest.NewServer(newRedactRouter(t, upstream, &redactAuth{secret: secret}))
	defer gw.Close()

	resp, codes, leaked := getWith1xxTrace(t, gw.URL+"/u/x")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Empty(t, codes, "1xx responses must not be forwarded on credentialed routes")
	assert.Empty(t, leaked)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Bearer [REDACTED]", resp.Header.Get("X-Final"))
	assert.Equal(t, "ok [REDACTED]", string(body))
}

func TestRouter_InformationalResponsesForwardedWithoutCredentials(t *testing.T) {
	upstream := informationalUpstream("nothing-secret")
	defer upstream.Close()
	gw := httptest.NewServer(newRedactRouter(t, upstream, auth.NewNoneAuth()))
	defer gw.Close()

	resp, codes, _ := getWith1xxTrace(t, gw.URL+"/u/x")
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, codes, http.StatusEarlyHints)
}
