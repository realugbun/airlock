package secrets

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProvider struct {
	values map[string]string
}

func (m *mockProvider) GetSecret(_ context.Context, path, key string) (string, error) {
	val, ok := m.values[path+":"+key]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return val, nil
}

func TestRegistry_Get(t *testing.T) {
	reg := NewRegistry()
	mp := &mockProvider{values: map[string]string{"p:k": "v"}}
	reg.Register("test", mp)

	p, err := reg.Get("test")
	require.NoError(t, err)
	assert.Equal(t, mp, p)
}

func TestRegistry_Get_NotFound(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.Get("missing")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSecretRef_Resolve(t *testing.T) {
	reg := NewRegistry()
	mp := &mockProvider{values: map[string]string{"secret/openai:api-key": "sk-test"}}
	reg.Register("vault", mp)

	ref := SecretRef{From: "vault", Path: "secret/openai", Key: "api-key"}
	val, err := ref.Resolve(context.Background(), reg)
	require.NoError(t, err)
	assert.Equal(t, "sk-test", val)
}

func TestSecretRef_Resolve_ProviderNotFound(t *testing.T) {
	reg := NewRegistry()
	ref := SecretRef{From: "missing", Path: "p", Key: "k"}
	_, err := ref.Resolve(context.Background(), reg)
	assert.Error(t, err)
}
