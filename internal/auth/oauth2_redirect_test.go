package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/realugbun/airlock/pkg/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newRedirectOAuth builds a provider whose three secrets resolve to the given
// values, pointed at tokenURL.
func newRedirectOAuth(tokenURL string, client *http.Client) *OAuth2Auth {
	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, "p", "client-id").
		Return("client-id-value", nil)
	mockProvider.On("GetSecret", mock.Anything, "p", "client-secret").
		Return("client-secret-value", nil)
	mockProvider.On("GetSecret", mock.Anything, "p", "refresh-token").
		Return("refresh-token-value", nil)

	registry := secrets.NewRegistry()
	registry.Register("vault", mockProvider)

	return NewOAuth2Auth(registry, OAuth2AuthConfig{
		ClientID:     secrets.SecretRef{From: "vault", Path: "p", Key: "client-id"},
		ClientSecret: secrets.SecretRef{From: "vault", Path: "p", Key: "client-secret"},
		RefreshToken: secrets.SecretRef{From: "vault", Path: "p", Key: "refresh-token"},
		TokenURL:     tokenURL,
		Header:       "Authorization",
		Prefix:       "Bearer ",
		HTTPClient:   client,
	})
}

// A token endpoint that answers a redirect must not have its request replayed
// against the redirect target: the form body carries the refresh token and the
// client credentials. The refresh fails instead, so no proxied request is
// forwarded with a credential.
func TestOAuth2Auth_TokenEndpointRedirectNotFollowed(t *testing.T) {
	// 301 and 302 drop the body on the replay; 307 and 308 replay it verbatim,
	// which is the leak. All four must be refused.
	for _, code := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var targetHits atomic.Int64
			var targetSawCredential atomic.Bool

			// The redirect target: a second server, standing in for any host
			// the token endpoint could name.
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				if err := r.ParseForm(); err == nil {
					if r.FormValue("refresh_token") != "" ||
						r.FormValue("client_secret") != "" ||
						r.FormValue("client_id") != "" {
						targetSawCredential.Store(true)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "stolen-token",
					"expires_in":   3600,
				})
			}))
			defer target.Close()

			var tokenHits atomic.Int64
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tokenHits.Add(1)
				http.Redirect(w, r, target.URL+"/token", code)
			}))
			defer tokenServer.Close()

			oauthAuth := newRedirectOAuth(tokenServer.URL, nil)

			req := httptest.NewRequest("GET", "/test", nil)
			redact, err := oauthAuth.AddAuth(context.Background(), req)

			require.Error(t, err, "a redirect from the token endpoint must fail the refresh")
			assert.Nil(t, redact)
			assert.Contains(t, err.Error(), "token endpoint returned")
			assert.Equal(t, int64(1), tokenHits.Load(), "the token endpoint is called exactly once")
			assert.Equal(t, int64(0), targetHits.Load(), "the redirect target must receive no request")
			assert.False(t, targetSawCredential.Load())

			// No credential reached the outgoing request either.
			assert.Empty(t, req.Header.Get("Authorization"))
			assert.NotContains(t, err.Error(), "refresh-token-value")
			assert.NotContains(t, err.Error(), "client-secret-value")
		})
	}
}

// A caller-supplied HTTPClient is not mutated: the provider uses a copy with
// CheckRedirect set, and the caller's own client still follows redirects.
func TestOAuth2Auth_CallerClientNotMutated(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"stolen-token","expires_in":3600}`))
	}))
	defer target.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer tokenServer.Close()

	caller := &http.Client{Timeout: 5 * time.Second}
	oauthAuth := newRedirectOAuth(tokenServer.URL, caller)

	req := httptest.NewRequest("GET", "/test", nil)
	_, err := oauthAuth.AddAuth(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, int64(0), targetHits.Load(), "the redirect target must receive no request")

	// The caller's client is untouched.
	assert.Nil(t, caller.CheckRedirect, "the caller's client must not be mutated")
	assert.NotSame(t, caller, oauthAuth.httpClient)
	assert.Equal(t, 5*time.Second, oauthAuth.httpClient.Timeout, "the caller's settings are kept")

	// Proof the caller's client still follows redirects.
	resp, err := caller.Get(tokenServer.URL)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int64(1), targetHits.Load())
}

// With no caller-supplied client the provider still gets the 30s timeout it
// always had, plus the redirect refusal.
func TestOAuth2Auth_DefaultClientKeepsTimeout(t *testing.T) {
	oauthAuth := newRedirectOAuth("http://127.0.0.1:1/token", nil)
	assert.Equal(t, 30*time.Second, oauthAuth.httpClient.Timeout)
	require.NotNil(t, oauthAuth.httpClient.CheckRedirect)
	assert.Equal(t, http.ErrUseLastResponse,
		oauthAuth.httpClient.CheckRedirect(nil, nil))
}
