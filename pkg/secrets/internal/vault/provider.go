package vault

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config holds Vault provider settings.
type Config struct {
	Address    string
	TokenPath  string
	SkipVerify bool
	CacheTTL   time.Duration
}

type cacheEntry struct {
	value  string
	expiry time.Time
}

// Provider reads secrets from HashiCorp Vault KV v2.
type Provider struct {
	client   *vaultapi.Client
	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]cacheEntry
}

// New creates a Vault secret provider.
func New(cfg Config) (*Provider, error) {
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = cfg.Address

	if cfg.SkipVerify {
		vaultCfg.HttpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	tokenBytes, err := os.ReadFile(cfg.TokenPath)
	if err != nil {
		return nil, fmt.Errorf("reading vault token from %s: %w", cfg.TokenPath, err)
	}
	client.SetToken(strings.TrimSpace(string(tokenBytes)))

	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	return &Provider{
		client:   client,
		cacheTTL: ttl,
		cache:    make(map[string]cacheEntry),
	}, nil
}

// GetSecret reads a key from a Vault KV v2 secret.
// Path should be in the form "mount/secret-name" (e.g. "secret/openai").
func (p *Provider) GetSecret(ctx context.Context, path, key string) (string, error) {
	cacheKey := path + ":" + key

	p.mu.RLock()
	if entry, ok := p.cache[cacheKey]; ok && time.Now().Before(entry.expiry) {
		p.mu.RUnlock()
		return entry.value, nil
	}
	p.mu.RUnlock()

	apiPath := insertKVv2Data(path)

	secret, err := p.client.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		return "", fmt.Errorf("reading vault secret %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault secret %s not found", path)
	}

	// KV v2 nests values under a "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		data = secret.Data
	}

	val, ok := data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in vault secret %s", key, path)
	}

	valStr, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("vault secret %s key %q is not a string", path, key)
	}

	p.mu.Lock()
	p.cache[cacheKey] = cacheEntry{value: valStr, expiry: time.Now().Add(p.cacheTTL)}
	p.mu.Unlock()

	return valStr, nil
}

// insertKVv2Data converts "secret/openai" to "secret/data/openai".
func insertKVv2Data(path string) string {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return path
	}
	return parts[0] + "/data/" + parts[1]
}
