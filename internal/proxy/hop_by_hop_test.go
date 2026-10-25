package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staticHeaderAuth struct{}

func (*staticHeaderAuth) AddAuth(_ context.Context, r *http.Request) ([]string, error) {
	r.Header.Set("Authorization", "Bearer real-secret")
	return []string{"real-secret", "Bearer real-secret"}, nil
}

func TestRouter_ConnectionNominatedHeadersCannotRemoveInjectedHeaders(t *testing.T) {
	cases := map[string][]string{
		"single line":           {"Authorization, X-Security-Scope"},
		"multiple lines":        {"Authorization", "X-Security-Scope"},
		"mixed case":            {"aUtHoRiZaTiOn,x-security-SCOPE"},
		"whitespace and commas": {" , authorization ,\tX-Security-Scope ,, "},
		"keep-alive form":       {"keep-alive, Authorization", "close, x-security-scope"},
		"with upgrade":          {"Upgrade, Authorization, X-Security-Scope"},
	}
	for name, connection := range cases {
		t.Run(name, func(t *testing.T) {
			seen := make(chan http.Header, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Clone()
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			upstreamURL, err := url.Parse(upstream.URL)
			require.NoError(t, err)
			access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "GET", Path: "/"}}, false)
			require.NoError(t, err)
			router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "test", "")})
			router.AddRoute(&Route{
				PathPrefix: "/u", StripPrefix: "/u", Upstream: upstreamURL,
				Auth: &staticHeaderAuth{}, Access: access,
				ExtraHeaders: map[string]string{"X-Security-Scope": "restricted"},
			})

			req := httptest.NewRequest(http.MethodGet, "/u", nil)
			req.Header["Connection"] = connection
			req.Header.Set("Keep-Alive", "timeout=5")
			req.Header.Set("Proxy-Connection", "keep-alive")
			req.Header.Set("Upgrade", "websocket")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req.WithContext(airlocklog.WithCorrelationID(context.Background(), "t")))
			got := <-seen

			assert.Equal(t, "Bearer real-secret", got.Get("Authorization"))
			assert.Equal(t, "restricted", got.Get("X-Security-Scope"))
			assert.Empty(t, got.Get("Keep-Alive"))
			assert.Empty(t, got.Get("Proxy-Connection"))
		})
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	h := http.Header{}
	h["Connection"] = []string{"X-A, x-b", " X-C "}
	h.Set("X-A", "1")
	h.Set("X-B", "2")
	h.Set("X-C", "3")
	h.Set("X-Keep", "4")
	h.Set("Te", "trailers, deflate")
	h.Set("Trailer", "X-T")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Proxy-Authorization", "Basic abc")
	removeHopByHopHeaders(h)

	assert.Empty(t, h.Values("X-A"))
	assert.Empty(t, h.Values("X-B"))
	assert.Empty(t, h.Values("X-C"))
	assert.Empty(t, h.Values("Connection"))
	assert.Empty(t, h.Values("Trailer"))
	assert.Empty(t, h.Values("Transfer-Encoding"))
	assert.Empty(t, h.Values("Proxy-Authorization"))
	assert.Equal(t, "4", h.Get("X-Keep"))
	assert.Equal(t, "trailers", h.Get("Te"))

	// An upgrade request survives in canonical form, nominating nothing else.
	h = http.Header{}
	h["Connection"] = []string{"keep-alive, Upgrade, Authorization"}
	h.Set("Upgrade", "websocket")
	h.Set("Authorization", "agent-supplied")
	removeHopByHopHeaders(h)
	assert.Equal(t, []string{"Upgrade"}, h.Values("Connection"))
	assert.Equal(t, "websocket", h.Get("Upgrade"))
	assert.Empty(t, h.Get("Authorization"))
}
