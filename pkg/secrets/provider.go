package secrets

import "context"

// SecretProvider resolves secret values from a backend.
type SecretProvider interface {
	GetSecret(ctx context.Context, path, key string) (string, error)
}

// SecretRef is a reference to a secret in a provider.
type SecretRef struct {
	From string `yaml:"from"`
	Path string `yaml:"path"`
	Key  string `yaml:"key"`
}

// Resolve fetches the secret value using the given registry.
func (r SecretRef) Resolve(ctx context.Context, reg *Registry) (string, error) {
	p, err := reg.Get(r.From)
	if err != nil {
		return "", err
	}
	return p.GetSecret(ctx, r.Path, r.Key)
}
