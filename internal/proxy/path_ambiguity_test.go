package proxy

import (
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

func TestHasAmbiguousPath(t *testing.T) {
	for _, p := range []string{
		"/..", "/.", "/a/..", "/a/.", "/a/../b", "/a/./b", "../a", "./a", "..", ".",
		"/a/b/..", `/a\b`, `\`, `/a/..\b`,
	} {
		assert.True(t, hasAmbiguousPath(p), p)
	}
	for _, p := range []string{
		"/", "/a", "/a.", "/.a", "/a..", "/..a", "/a/.../b", "/a/b.c/d", "//a", "/a/",
	} {
		assert.False(t, hasAmbiguousPath(p), p)
	}
}

func TestRouter_RejectsDotSegmentsAndBackslashes(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "ALL", Path: "/**"}}, false)
	require.NoError(t, err)
	router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "test", "")})
	router.AddRoute(&Route{
		PathPrefix: "/api", StripPrefix: "/api", Upstream: upstreamURL,
		Auth: auth.NewNoneAuth(), Access: access,
	})
	gw := httptest.NewServer(router)
	defer gw.Close()

	for _, p := range []string{
		"/api/allowed/../admin",
		"/api/allowed/./x",
		"/api/allowed/..",
		"/api/allowed/%2e%2e/admin",
		"/api/allowed/%2E%2E/admin",
		"/api/allowed/.%2e/admin",
		"/api/allowed/%2e./admin",
		"/api/allowed/%2e/admin",
		"/api/..",
		"/api/%2e%2e",
		// Only a dot segment once strip_prefix is applied.
		"/api../admin",
		"/api%2e%2e/admin",
		"/api./x",
		// Literal backslash.
		`/api/allowed\..\admin`,
		`/api/a\b`,
	} {
		t.Run(p, func(t *testing.T) {
			resp, err := http.Get(gw.URL + p)
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
	assert.Zero(t, hits.Load(), "no ambiguous path may reach the upstream")

	for _, p := range []string{"/api/a.b/c", "/api/...", "/api/.well-known/x", "/api/v1..2"} {
		resp, err := http.Get(gw.URL + p)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, p)
	}
}

func TestRouter_RejectsLiteralBackslashInDecodedPath(t *testing.T) {
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "ALL", Path: "/**"}}, false)
	require.NoError(t, err)
	upstreamURL, _ := url.Parse("http://127.0.0.1:1")
	router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "test", "")})
	router.AddRoute(&Route{PathPrefix: "/api", StripPrefix: "/api", Upstream: upstreamURL, Auth: auth.NewNoneAuth(), Access: access})

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.URL.Path = `/api/allowed\..\admin`
	req.URL.RawPath = ""
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
