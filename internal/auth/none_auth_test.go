package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoneAuth_AddAuthInjectsNothing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/file/abc/binary?token=signed", nil)
	req.Header.Set("Accept", "application/json")
	before := req.Header.Clone()

	redact, err := NewNoneAuth().AddAuth(context.Background(), req)
	if err != nil {
		t.Fatalf("AddAuth returned error: %v", err)
	}
	if redact != nil {
		t.Errorf("expected no redact values, got %v", redact)
	}
	if len(req.Header) != len(before) {
		t.Errorf("header count changed: before %d, after %d", len(before), len(req.Header))
	}
	for k, v := range before {
		if got := req.Header[k]; len(got) != len(v) || (len(v) > 0 && got[0] != v[0]) {
			t.Errorf("header %q mutated: before %v, after %v", k, v, got)
		}
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("NoneAuth must not set an Authorization header")
	}
}

func TestNoneAuth_DoesNotStripExistingHeaders(t *testing.T) {
	// strip_agent_auth is the router's job, not the auth provider's. NoneAuth
	// must leave whatever the router handed it untouched.
	req := httptest.NewRequest(http.MethodGet, "https://example.com/x", nil)
	req.Header.Set("Authorization", "Bearer agent-token")

	if _, err := NewNoneAuth().AddAuth(context.Background(), req); err != nil {
		t.Fatalf("AddAuth returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer agent-token" {
		t.Errorf("Authorization changed: got %q, want %q", got, "Bearer agent-token")
	}
}

func TestNoneAuth_ImplementsAuthProvider(t *testing.T) {
	var _ AuthProvider = NewNoneAuth()
}
