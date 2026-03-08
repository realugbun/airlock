package auth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/realugbun/airlock/pkg/secrets"
	"go.opentelemetry.io/otel"
)

var tracer = otel.Tracer("github.com/realugbun/airlock")

// StaticAuthConfig configures a static token auth provider.
type StaticAuthConfig struct {
	Token  secrets.SecretRef
	Header string
	Prefix string
	TTL    time.Duration
}

// StaticAuth injects a static token (e.g. API key) into requests.
type StaticAuth struct {
	registry *secrets.Registry
	ref      secrets.SecretRef
	header   string
	prefix   string
	ttl      time.Duration

	mu     sync.Mutex
	cached string
	expiry time.Time
}

// NewStaticAuth creates a static token auth provider.
func NewStaticAuth(registry *secrets.Registry, cfg StaticAuthConfig) *StaticAuth {
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &StaticAuth{
		registry: registry,
		ref:      cfg.Token,
		header:   cfg.Header,
		prefix:   cfg.Prefix,
		ttl:      ttl,
	}
}

// AddAuth resolves the token and sets the header on the request.
// Returns the credential values for response redaction.
func (s *StaticAuth) AddAuth(ctx context.Context, req *http.Request) ([]string, error) {
	token, err := s.getToken(ctx)
	if err != nil {
		return nil, err
	}
	headerValue := s.prefix + token
	req.Header.Set(s.header, headerValue)
	redact := []string{token}
	if headerValue != token {
		redact = append(redact, headerValue)
	}
	return redact, nil
}

func (s *StaticAuth) getToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cached != "" && time.Now().Before(s.expiry) {
		return s.cached, nil
	}

	ctx, span := tracer.Start(ctx, "auth.static.refresh")
	defer span.End()

	token, err := s.ref.Resolve(ctx, s.registry)
	if err != nil {
		return "", err
	}

	s.cached = token
	s.expiry = time.Now().Add(s.ttl)
	return token, nil
}
