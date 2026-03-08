package auth

import (
	"context"
	"net/http"
)

// AuthProvider injects credentials into an outbound HTTP request.
// AddAuth returns the credential strings that were injected, so they can be
// redacted from upstream responses before the agent sees them.
type AuthProvider interface {
	AddAuth(ctx context.Context, req *http.Request) (redact []string, err error)
}
