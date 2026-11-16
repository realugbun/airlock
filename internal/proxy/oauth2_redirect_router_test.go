package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/realugbun/airlock/internal/auth"
	"github.com/realugbun/airlock/pkg/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End to end: a route whose OAuth2 token endpoint answers a redirect. The
// refresh fails, so the request is refused before the upstream is contacted
// and no proxied request carries a credential. The redirect target, which
// stands in for whatever host the token endpoint names, gets no request at
// all, so it never sees the refresh token or the client secret that the token
// request's form body carries.
func TestRouter_OAuth2TokenRedirectNotFollowed(t *testing.T) {
	const (
		clientID     = "cid-abcdefg"
		clientSecret = "csec-hijklmn"
		refreshToken = "rtok-opqrstu"
	)
	t.Setenv("AIRLOCK_TEST_CLIENT_ID", clientID)
	t.Setenv("AIRLOCK_TEST_CLIENT_SECRET", clientSecret)
	t.Setenv("AIRLOCK_TEST_REFRESH_TOKEN", refreshToken)

	var targetHits atomic.Int64
	var targetBodies bytes.Buffer
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		b, _ := io.ReadAll(r.Body)
		targetBodies.Write(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"stolen-token","expires_in":3600}`))
	}))
	defer target.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer tokenServer.Close()

	var upstreamHits atomic.Int64
	var upstreamAuth atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		upstreamAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("should never be reached"))
	}))
	defer upstream.Close()

	registry := secrets.NewRegistry()
	registry.Register("env", secrets.NewEnvProvider())
	provider := auth.NewOAuth2Auth(registry, auth.OAuth2AuthConfig{
		ClientID:     secrets.SecretRef{From: "env", Key: "AIRLOCK_TEST_CLIENT_ID"},
		ClientSecret: secrets.SecretRef{From: "env", Key: "AIRLOCK_TEST_CLIENT_SECRET"},
		RefreshToken: secrets.SecretRef{From: "env", Key: "AIRLOCK_TEST_REFRESH_TOKEN"},
		TokenURL:     tokenServer.URL,
		Header:       "Authorization",
		Prefix:       "Bearer ",
	})

	var logs bytes.Buffer
	gw := httptest.NewServer(newRedactRouterWithLog(t, upstream, provider, &logs))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/u/x")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.GreaterOrEqual(t, resp.StatusCode, 500, "the refresh failure must fail closed")
	assert.Less(t, resp.StatusCode, 600)

	assert.Equal(t, int64(0), targetHits.Load(), "the redirect target must receive no request")
	assert.Empty(t, targetBodies.String())
	assert.Equal(t, int64(0), upstreamHits.Load(), "no proxied request is forwarded")
	assert.Nil(t, upstreamAuth.Load(), "no credential reached the upstream")

	for _, secret := range []string{clientID, clientSecret, refreshToken, "stolen-token"} {
		assert.NotContains(t, string(body), secret, "the response must not leak %q", secret)
		assert.NotContains(t, logs.String(), secret, "the log must not contain %q", secret)
	}
	assert.Contains(t, logs.String(), "auth injection failed")
}
