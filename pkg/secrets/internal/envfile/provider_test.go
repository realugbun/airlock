package envfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvFileProvider_GetSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.env")
	content := `# Comment line
API_KEY=sk-test-123
DB_PASSWORD="quoted-value"
EMPTY=
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	p, err := New(path)
	require.NoError(t, err)

	val, err := p.GetSecret(context.Background(), "", "API_KEY")
	require.NoError(t, err)
	assert.Equal(t, "sk-test-123", val)

	val, err = p.GetSecret(context.Background(), "", "DB_PASSWORD")
	require.NoError(t, err)
	assert.Equal(t, "quoted-value", val)
}

func TestEnvFileProvider_GetSecret_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.env")
	require.NoError(t, os.WriteFile(path, []byte("A=B\n"), 0600))

	p, err := New(path)
	require.NoError(t, err)

	_, err = p.GetSecret(context.Background(), "", "MISSING")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestEnvFileProvider_FileNotFound(t *testing.T) {
	_, err := New("/nonexistent/path.env")
	assert.Error(t, err)
}
