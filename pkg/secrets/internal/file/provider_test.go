package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileProvider_GetSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("  my-secret-value  \n"), 0600))

	p := New()
	val, err := p.GetSecret(context.Background(), path, "")

	require.NoError(t, err)
	assert.Equal(t, "my-secret-value", val)
}

func TestFileProvider_GetSecret_NotFound(t *testing.T) {
	p := New()
	_, err := p.GetSecret(context.Background(), "/nonexistent/path", "")
	assert.Error(t, err)
}
