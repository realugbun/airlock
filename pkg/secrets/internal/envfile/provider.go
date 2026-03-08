package envfile

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Provider reads secrets from a KEY=VALUE file on disk.
type Provider struct {
	path string
	mu   sync.RWMutex
	data map[string]string
}

// New creates an envfile provider that reads from the given path.
func New(path string) (*Provider, error) {
	p := &Provider{
		path: path,
		data: make(map[string]string),
	}
	if err := p.load(); err != nil {
		return nil, err
	}
	return p, nil
}

// GetSecret returns the value for the given key from the env file.
// The path parameter is ignored. The file is re-read on each call to pick up changes.
func (p *Provider) GetSecret(_ context.Context, _, key string) (string, error) {
	if err := p.load(); err != nil {
		return "", err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	val, ok := p.data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in env file %s", key, p.path)
	}
	return val, nil
}

func (p *Provider) load() error {
	f, err := os.Open(p.path)
	if err != nil {
		return fmt.Errorf("opening env file: %w", err)
	}
	defer func() { _ = f.Close() }()

	data := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		data[key] = val
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading env file: %w", err)
	}

	p.mu.Lock()
	p.data = data
	p.mu.Unlock()

	return nil
}
