package auth

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/realugbun/airlock/pkg/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockSecretProvider struct {
	mock.Mock
}

func (m *MockSecretProvider) GetSecret(ctx context.Context, path, key string) (string, error) {
	args := m.Called(ctx, path, key)
	return args.String(0), args.Error(1)
}

func TestStaticAuth_AddAuth(t *testing.T) {
	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, "secret/openai", "api-key").
		Return("sk-test-123", nil)

	registry := secrets.NewRegistry()
	registry.Register("vault", mockProvider)

	auth := NewStaticAuth(registry, StaticAuthConfig{
		Token:  secrets.SecretRef{From: "vault", Path: "secret/openai", Key: "api-key"},
		Header: "Authorization",
		Prefix: "Bearer ",
	})

	req := httptest.NewRequest("GET", "/v1/chat/completions", nil)
	redact, err := auth.AddAuth(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "Bearer sk-test-123", req.Header.Get("Authorization"))
	assert.Contains(t, redact, "sk-test-123")
	assert.Contains(t, redact, "Bearer sk-test-123")
	mockProvider.AssertExpectations(t)
}

func TestStaticAuth_CachesToken(t *testing.T) {
	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, "secret/openai", "api-key").
		Return("sk-test-123", nil).Once()

	registry := secrets.NewRegistry()
	registry.Register("vault", mockProvider)

	auth := NewStaticAuth(registry, StaticAuthConfig{
		Token:  secrets.SecretRef{From: "vault", Path: "secret/openai", Key: "api-key"},
		Header: "Authorization",
		Prefix: "Bearer ",
	})

	req1 := httptest.NewRequest("GET", "/test", nil)
	_, err := auth.AddAuth(context.Background(), req1)
	require.NoError(t, err)

	req2 := httptest.NewRequest("GET", "/test", nil)
	redact, err := auth.AddAuth(context.Background(), req2)
	require.NoError(t, err)

	assert.Equal(t, "Bearer sk-test-123", req2.Header.Get("Authorization"))
	assert.Contains(t, redact, "sk-test-123")
	mockProvider.AssertNumberOfCalls(t, "GetSecret", 1)
}

func TestStaticAuth_NoPrefix(t *testing.T) {
	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, "", "API_KEY").
		Return("my-api-key", nil)

	registry := secrets.NewRegistry()
	registry.Register("env", mockProvider)

	auth := NewStaticAuth(registry, StaticAuthConfig{
		Token:  secrets.SecretRef{From: "env", Key: "API_KEY"},
		Header: "X-Api-Key",
		Prefix: "",
	})

	req := httptest.NewRequest("GET", "/test", nil)
	redact, err := auth.AddAuth(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "my-api-key", req.Header.Get("X-Api-Key"))
	// With no prefix, token == headerValue, so only one entry
	assert.Equal(t, []string{"my-api-key"}, redact)
}

func TestStaticAuth_SecretError(t *testing.T) {
	mockProvider := new(MockSecretProvider)
	mockProvider.On("GetSecret", mock.Anything, "secret/openai", "api-key").
		Return("", fmt.Errorf("vault unreachable"))

	registry := secrets.NewRegistry()
	registry.Register("vault", mockProvider)

	auth := NewStaticAuth(registry, StaticAuthConfig{
		Token:  secrets.SecretRef{From: "vault", Path: "secret/openai", Key: "api-key"},
		Header: "Authorization",
		Prefix: "Bearer ",
	})

	req := httptest.NewRequest("GET", "/test", nil)
	redact, err := auth.AddAuth(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, redact)
}
