package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/realugbun/airlock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMethodOverrideHeader(t *testing.T) {
	for _, name := range []string{
		"X-HTTP-Method-Override", "x-http-method-override", "X-Http-Method-Override",
		"X-HTTP-METHOD", "x-http-method", "X-Method-Override", "x-mEtHoD-oVeRrIdE",
	} {
		h := http.Header{}
		h[name] = []string{"DELETE"}
		assert.NotEmpty(t, methodOverrideHeader(h), name)
	}

	for _, name := range []string{
		"X-Method", "X-Override", "X-HTTP-Method-Override-Not", "Content-Type",
	} {
		h := http.Header{}
		h[name] = []string{"DELETE"}
		assert.Empty(t, methodOverrideHeader(h), name)
	}

	assert.Empty(t, methodOverrideHeader(http.Header{}))
}

// A route that allows POST /x must refuse a POST that also carries a method
// override header, in any header-name case, without contacting the upstream.
func TestRouter_RejectsMethodOverrideHeaders(t *testing.T) {
	up := newRecordingUpstream(t)
	access, err := NewAccessPolicy([]AccessRuleInput{
		{Action: "ALLOW", Method: "POST", Path: "/x"},
		{Action: "DENY", Method: "ALL", Path: "/**"},
	}, false)
	require.NoError(t, err)

	gw := newBoundaryRouter(t, &Route{
		PathPrefix: "/r", StripPrefix: "/r", Upstream: up.url(t),
		Auth: auth.NewNoneAuth(), Access: access,
	})

	for _, name := range []string{
		"X-HTTP-Method-Override",
		"x-http-method-override",
		"X-HTTP-METHOD-OVERRIDE",
		"X-HTTP-Method",
		"x-http-method",
		"X-Method-Override",
		"x-method-override",
		"X-mEtHoD-oVeRrIdE",
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, gw.URL+"/r/x", strings.NewReader("{}"))
			require.NoError(t, err)
			// Set the key verbatim so the wire carries this exact casing.
			req.Header[name] = []string{"DELETE"}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, string(body), "method override")
		})
	}

	assert.Zero(t, up.hits.Load(), "no override request may reach the upstream")

	// The same request without the header is proxied.
	resp, err := http.Post(gw.URL+"/r/x", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(1), up.hits.Load())
}

// The rejection happens before routing, so it applies to paths that match no
// route and to the method the policy would otherwise have allowed.
func TestRouter_MethodOverrideRejectedBeforeRouting(t *testing.T) {
	up := newRecordingUpstream(t)
	gw := newBoundaryRouter(t, &Route{
		PathPrefix: "/r", StripPrefix: "/r", Upstream: up.url(t),
		Auth: auth.NewNoneAuth(), Access: allowAll(t),
	})

	req, err := http.NewRequest(http.MethodGet, gw.URL+"/no-such-route", nil)
	require.NoError(t, err)
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Zero(t, up.hits.Load())
}

// The health endpoint is answered before any request inspection.
func TestRouter_HealthzIgnoresMethodOverride(t *testing.T) {
	up := newRecordingUpstream(t)
	router := NewRouter(RouterConfig{Logger: testDiscardLogger()})
	router.SetRoutes([]*Route{{
		PathPrefix: "/r", StripPrefix: "/r", Upstream: up.url(t),
		Auth: auth.NewNoneAuth(), Access: allowAll(t),
	}})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
