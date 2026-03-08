package secrets

import "fmt"

// Registry maps provider names to SecretProvider instances.
type Registry struct {
	providers map[string]SecretProvider
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]SecretProvider)}
}

// Register adds a provider under the given name.
func (r *Registry) Register(name string, p SecretProvider) {
	r.providers[name] = p
}

// Get returns the provider registered under the given name.
func (r *Registry) Get(name string) (SecretProvider, error) {
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("secret provider %q not found", name)
	}
	return p, nil
}
