package file

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Provider reads a secret from a raw file on disk.
type Provider struct{}

// New creates a file secret provider.
func New() *Provider {
	return &Provider{}
}

// GetSecret reads the entire file at path and returns its trimmed content.
// The key parameter is ignored.
func (p *Provider) GetSecret(_ context.Context, path, _ string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading secret file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}
