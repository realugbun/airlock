package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/realugbun/airlock/pkg/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestOAuth2Auth_AddAuth(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "test-refresh", r.FormValue("refresh_token"))
		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		assert.Equal(t, "test-client-secret", r.FormValue("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "access-token-123",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, "secret/oauth", "client-id").
		Return("test-client-id", nil)
	mockProvider.On("GetSecret", mock.Anything, "secret/oauth", "client-secret").
		Return("test-client-secret", nil)
	mockProvider.On("GetSecret", mock.Anything, "secret/oauth", "refresh-token").
		Return("test-refresh", nil)

	registry := secrets.NewRegistry()
	registry.Register("vault", mockProvider)

	oauthAuth := NewOAuth2Auth(registry, OAuth2AuthConfig{
		ClientID:     secrets.SecretRef{From: "vault", Path: "secret/oauth", Key: "client-id"},
		ClientSecret: &secrets.SecretRef{From: "vault", Path: "secret/oauth", Key: "client-secret"},
		RefreshToken: secrets.SecretRef{From: "vault", Path: "secret/oauth", Key: "refresh-token"},
		TokenURL:     tokenServer.URL,
		Header:       "Authorization",
		Prefix:       "Bearer ",
	})

	req := httptest.NewRequest("GET", "/test", nil)
	redact, err := oauthAuth.AddAuth(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "Bearer access-token-123", req.Header.Get("Authorization"))
	assert.Contains(t, redact, "access-token-123")
	assert.Contains(t, redact, "Bearer access-token-123")
	mockProvider.AssertExpectations(t)
}

func TestOAuth2Auth_CachesToken(t *testing.T) {
	callCount := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "access-token-123",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, mock.Anything, mock.Anything).
		Return("value", nil)

	registry := secrets.NewRegistry()
	registry.Register("vault", mockProvider)

	oauthAuth := NewOAuth2Auth(registry, OAuth2AuthConfig{
		ClientID:     secrets.SecretRef{From: "vault", Path: "p", Key: "k"},
		ClientSecret: &secrets.SecretRef{From: "vault", Path: "p", Key: "k"},
		RefreshToken: secrets.SecretRef{From: "vault", Path: "p", Key: "k"},
		TokenURL:     tokenServer.URL,
		Header:       "Authorization",
		Prefix:       "Bearer ",
	})

	req1 := httptest.NewRequest("GET", "/test", nil)
	_, err := oauthAuth.AddAuth(context.Background(), req1)
	require.NoError(t, err)

	req2 := httptest.NewRequest("GET", "/test", nil)
	_, err = oauthAuth.AddAuth(context.Background(), req2)
	require.NoError(t, err)

	assert.Equal(t, 1, callCount)
}

func TestOAuth2Auth_TokenEndpointError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tokenServer.Close()

	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, mock.Anything, mock.Anything).
		Return("value", nil)

	registry := secrets.NewRegistry()
	registry.Register("vault", mockProvider)

	oauthAuth := NewOAuth2Auth(registry, OAuth2AuthConfig{
		ClientID:     secrets.SecretRef{From: "vault", Path: "p", Key: "k"},
		ClientSecret: &secrets.SecretRef{From: "vault", Path: "p", Key: "k"},
		RefreshToken: secrets.SecretRef{From: "vault", Path: "p", Key: "k"},
		TokenURL:     tokenServer.URL,
		Header:       "Authorization",
		Prefix:       "Bearer ",
	})

	req := httptest.NewRequest("GET", "/test", nil)
	redact, err := oauthAuth.AddAuth(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Nil(t, redact)
}

func TestOAuth2Auth_PublicClient_NoClientSecret(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "test-refresh", r.FormValue("refresh_token"))
		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		// client_secret must NOT be present for public clients
		assert.Empty(t, r.FormValue("client_secret"), "client_secret should not be sent for public clients")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "public-access-token",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, "secret/oauth", "client-id").
		Return("test-client-id", nil)
	mockProvider.On("GetSecret", mock.Anything, "secret/oauth", "refresh-token").
		Return("test-refresh", nil)

	registry := secrets.NewRegistry()
	registry.Register("vault", mockProvider)

	oauthAuth := NewOAuth2Auth(registry, OAuth2AuthConfig{
		ClientID:     secrets.SecretRef{From: "vault", Path: "secret/oauth", Key: "client-id"},
		ClientSecret: nil, // public client — no client_secret
		RefreshToken: secrets.SecretRef{From: "vault", Path: "secret/oauth", Key: "refresh-token"},
		TokenURL:     tokenServer.URL,
		Header:       "Authorization",
		Prefix:       "Bearer ",
	})

	req := httptest.NewRequest("GET", "/test", nil)
	redact, err := oauthAuth.AddAuth(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "Bearer public-access-token", req.Header.Get("Authorization"))
	assert.Contains(t, redact, "public-access-token")
	mockProvider.AssertExpectations(t)
}
