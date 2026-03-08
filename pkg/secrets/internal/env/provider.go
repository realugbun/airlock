package env

import (
	"context"
	"fmt"
	"os"
)

// Provider reads secrets from environment variables.
type Provider struct{}

// New creates an env secret provider.
func New() *Provider {
	return &Provider{}
}

// GetSecret returns the value of the environment variable named by key.
// The path parameter is ignored.
func (p *Provider) GetSecret(_ context.Context, _, key string) (string, error) {
	val, ok := os.LookupEnv(key)
	if !ok {
		return "", fmt.Errorf("environment variable %q not found", key)
	}
	return val, nil
}
