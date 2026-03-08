package env

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvProvider_GetSecret(t *testing.T) {
	t.Setenv("TEST_API_KEY", "sk-test-123")

	p := New()
	val, err := p.GetSecret(context.Background(), "", "TEST_API_KEY")

	require.NoError(t, err)
	assert.Equal(t, "sk-test-123", val)
}

func TestEnvProvider_GetSecret_NotFound(t *testing.T) {
	p := New()
	_, err := p.GetSecret(context.Background(), "", "DOES_NOT_EXIST_XYZ")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
