package proxy

import (
	"io"
	"log/slog"
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

// recordingUpstream reports how many requests it received and the last path
// it was asked for.
type recordingUpstream struct {
	server   *httptest.Server
	hits     atomic.Int32
	lastPath atomic.Value
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	u.lastPath.Store("")
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.lastPath.Store(r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *recordingUpstream) url(t *testing.T) *url.URL {
	t.Helper()
	parsed, err := url.Parse(u.server.URL)
	require.NoError(t, err)
	return parsed
}

func (u *recordingUpstream) path() string {
	s, _ := u.lastPath.Load().(string)
	return s
}

func testDiscardLogger() *slog.Logger {
	return airlocklog.NewLogger(io.Discard, "test", "")
}

func newBoundaryRouter(t *testing.T, routes ...*Route) *httptest.Server {
	t.Helper()
	router := NewRouter(RouterConfig{Logger: testDiscardLogger()})
	router.SetRoutes(routes)
	gw := httptest.NewServer(router)
	t.Cleanup(gw.Close)
	return gw
}

func allowAll(t *testing.T) *AccessPolicy {
	t.Helper()
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "ALL", Path: "/**"}}, false)
	require.NoError(t, err)
	return access
}

// A route prefix matches whole segments, so "/git" must not capture
// "/github/...".
func TestRouter_PrefixMatchesOnSegmentBoundary(t *testing.T) {
	git := newRecordingUpstream(t)
	github := newRecordingUpstream(t)

	gw := newBoundaryRouter(t,
		&Route{
			PathPrefix: "/git", StripPrefix: "/git", Upstream: git.url(t),
			Auth: auth.NewNoneAuth(), Access: allowAll(t),
		},
		&Route{
			PathPrefix: "/github", StripPrefix: "/github", Upstream: github.url(t),
			Auth: auth.NewNoneAuth(), Access: allowAll(t),
		},
	)

	resp, err := http.Get(gw.URL + "/github/repos")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(1), github.hits.Load(), "the /github route must handle /github/repos")
	assert.Equal(t, "/repos", github.path())
	assert.Zero(t, git.hits.Load(), "the /git upstream must receive nothing")

	// The /git route still serves its own paths.
	resp, err = http.Get(gw.URL + "/git/repo/info/refs")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(1), git.hits.Load())
	assert.Equal(t, "/repo/info/refs", git.path())
	assert.Equal(t, int32(1), github.hits.Load())
}

// Paths that share a textual prefix but not a segment boundary match no route.
func TestRouter_NoRouteForPartialSegmentPrefix(t *testing.T) {
	up := newRecordingUpstream(t)
	gw := newBoundaryRouter(t, &Route{
		PathPrefix: "/git", StripPrefix: "/git", Upstream: up.url(t),
		Auth: auth.NewNoneAuth(), Access: allowAll(t),
	})

	for _, p := range []string{"/github/repos", "/gitlab", "/git-other", "/gitx/y"} {
		resp, err := http.Get(gw.URL + p)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, p)
	}
	assert.Zero(t, up.hits.Load(), "no upstream request for an unmatched path")
}

// A request for exactly the prefix is handled, and the upstream sees "/".
func TestRouter_RequestEqualToPrefix(t *testing.T) {
	up := newRecordingUpstream(t)
	gw := newBoundaryRouter(t, &Route{
		PathPrefix: "/api", StripPrefix: "/api", Upstream: up.url(t),
		Auth: auth.NewNoneAuth(), Access: allowAll(t),
	})

	for _, p := range []string{"/api", "/api/"} {
		resp, err := http.Get(gw.URL + p)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, p)
		assert.Equal(t, "/", up.path(), p)
	}
}

// A prefix configured with a trailing slash describes the same paths as one
// without, and stripping it leaves an absolute path.
func TestRouter_TrailingSlashPrefix(t *testing.T) {
	up := newRecordingUpstream(t)
	gw := newBoundaryRouter(t, &Route{
		PathPrefix: "/api/", StripPrefix: "/api/", Upstream: up.url(t),
		Auth: auth.NewNoneAuth(), Access: allowAll(t),
	})

	for _, tc := range []struct{ request, upstream string }{
		{"/api", "/"},
		{"/api/", "/"},
		{"/api/v1/users", "/v1/users"},
	} {
		resp, err := http.Get(gw.URL + tc.request)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, tc.request)
		assert.Equal(t, tc.upstream, up.path(), tc.request)
	}

	resp, err := http.Get(gw.URL + "/apifoo")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// The path the access policy checks is the path the upstream receives, for
// both an exact-prefix request and a trailing-slash prefix.
func TestRouter_AccessPolicySeesForwardedPath(t *testing.T) {
	up := newRecordingUpstream(t)
	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/v1/users"},
		{Action: "DENY", Method: "ALL", Path: "/**"},
	}, false)
	require.NoError(t, err)

	gw := newBoundaryRouter(t, &Route{
		PathPrefix: "/api/", StripPrefix: "/api/", Upstream: up.url(t),
		Auth: auth.NewNoneAuth(), Access: access,
	})

	resp, err := http.Get(gw.URL + "/api/v1/users")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/v1/users", up.path())

	resp, err = http.Get(gw.URL + "/api/v1/admin")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, int32(1), up.hits.Load())
}

// A query string is forwarded byte for byte and plays no part in matching.
func TestRouter_QueryStringForwardedUnchanged(t *testing.T) {
	var rawQuery atomic.Value
	rawQuery.Store("")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery.Store(r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "GET", Path: "/v1/users"},
		{Action: "DENY", Method: "ALL", Path: "/**"},
	}, false)
	require.NoError(t, err)

	gw := newBoundaryRouter(t, &Route{
		PathPrefix: "/api", StripPrefix: "/api", Upstream: upstreamURL,
		Auth: auth.NewNoneAuth(), Access: access,
	})

	// The query is not part of the path the rules match, and reaches the
	// upstream exactly as sent, including encoded characters.
	q := "a=1&b=%2Fadmin&c=x+y&d"
	resp, err := http.Get(gw.URL + "/api/v1/users?" + q)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, q, rawQuery.Load())
}
