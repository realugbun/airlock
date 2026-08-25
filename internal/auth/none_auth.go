package auth

import (
	"context"
	"net/http"
)

// NoneAuth is a passthrough auth provider that injects no credential.
//
// It exists for upstreams that carry their own authorization inside the request
// the agent already holds — for example a pre-signed URL whose query string
// contains a short-lived token, or a redirect target on a CDN host. Sending an
// unrelated credential to such a host would be needless exposure, but the route
// still needs to run through the gateway so that access rules, rate limiting and
// egress control apply.
//
// Because it injects nothing, it also returns no redact values: there is no
// gateway-held secret that could appear in the upstream response. Note that
// strip_agent_auth is independent of the auth type — a "none" route can (and
// usually should) still strip the agent's own Authorization header.
type NoneAuth struct{}

// NewNoneAuth creates a passthrough auth provider that injects no credential.
func NewNoneAuth() *NoneAuth {
	return &NoneAuth{}
}

// AddAuth is a no-op. It never modifies the request and never returns redact
// values, since no credential is injected.
func (n *NoneAuth) AddAuth(_ context.Context, _ *http.Request) ([]string, error) {
	return nil, nil
}
