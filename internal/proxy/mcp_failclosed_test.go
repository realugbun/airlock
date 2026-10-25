package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/realugbun/airlock/internal/auth"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allowlistPolicy(t *testing.T) *MCPToolPolicy {
	t.Helper()
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{AllowedTools: []string{"read"}})
	require.NoError(t, err)
	return p
}

func checkMCPBody(t *testing.T, p *MCPToolPolicy, body string, header http.Header) (*MCPCheckResult, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	return p.CheckRequest(req)
}

func TestMCP_ContentTypeVariantsAreInspected(t *testing.T) {
	p := allowlistPolicy(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}`
	for _, ct := range []string{
		"application/json",
		"Application/JSON",
		"APPLICATION/JSON; charset=UTF-8",
		"application/json;charset=utf-8",
		"text/json",
		" application/json ",
	} {
		t.Run(ct, func(t *testing.T) {
			res, err := checkMCPBody(t, p, body, http.Header{"Content-Type": {ct}})
			require.NoError(t, err)
			assert.True(t, res.Denied)
		})
	}
}

func TestMCP_EmptyContentTypeIsInspected(t *testing.T) {
	p := allowlistPolicy(t)
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}`))
	res, err := p.CheckRequest(req)
	require.NoError(t, err)
	assert.True(t, res.Denied)
}

func TestMCP_UnsupportedMediaTypeRejected(t *testing.T) {
	p := allowlistPolicy(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}`
	for _, ct := range []string{
		"text/plain",
		"application/x-www-form-urlencoded",
		"application/json-seq",
		"application/jsonx",
		"application/json; charset=utf-16",
		"not a media type;;",
	} {
		t.Run(ct, func(t *testing.T) {
			_, err := checkMCPBody(t, p, body, http.Header{"Content-Type": {ct}})
			requireMCPReject(t, err, http.StatusUnsupportedMediaType)
		})
	}
}

func TestMCP_MultipleContentTypesRejected(t *testing.T) {
	p := allowlistPolicy(t)
	_, err := checkMCPBody(t, p, `{}`, http.Header{"Content-Type": {"application/json", "text/plain"}})
	requireMCPReject(t, err, http.StatusBadRequest)
}

func TestMCP_ContentEncodingRejected(t *testing.T) {
	p := allowlistPolicy(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	for _, enc := range [][]string{
		{"gzip"},
		{"deflate"},
		{"GZIP"},
		{"br"},
		{"identity, gzip"},
		{"identity", "gzip"},
		{"gzip, gzip"},
	} {
		t.Run(strings.Join(enc, "|"), func(t *testing.T) {
			_, err := checkMCPBody(t, p, body, http.Header{"Content-Encoding": enc})
			requireMCPReject(t, err, http.StatusUnsupportedMediaType)
		})
	}

	res, err := checkMCPBody(t, p, body, http.Header{"Content-Encoding": {"identity"}})
	require.NoError(t, err)
	assert.False(t, res.Denied)
}

func TestMCP_StructurallyInvalidRequestsRejected(t *testing.T) {
	p := allowlistPolicy(t)
	for name, body := range map[string]string{
		"malformed":              `{"jsonrpc":"2.0","method":"tools/call",`,
		"trailing data":          `{"jsonrpc":"2.0","id":1,"method":"ping"} {"method":"tools/call"}`,
		"not an object":          `"tools/call"`,
		"null":                   `null`,
		"method not string":      `{"jsonrpc":"2.0","id":1,"method":7}`,
		"params null":            `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`,
		"params array":           `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["delete_all"]}`,
		"name missing":           `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
		"name empty":             `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}`,
		"name not string":        `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["delete_all"]}}`,
		"NaN id":                 `{"jsonrpc":"2.0","id":NaN,"method":"tools/call","params":{"name":"delete_all"}}`,
		"invalid utf8":           "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read\xff\"}}",
		"batch malformed":        `[{"jsonrpc":"2.0","id":1,"method":"ping"},`,
		"batch element scalar":   `[{"jsonrpc":"2.0","id":1,"method":"ping"}, 3]`,
		"batch element bad call": `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/call"}]`,
		"batch nested array":     `[[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}]]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := checkMCPBody(t, p, body, nil)
			requireMCPReject(t, err, http.StatusBadRequest)
		})
	}
}

// encoding/json matches keys case-insensitively and the last match wins. A
// case-sensitive upstream would run a different tool or method than the one
// checked, so duplicate and case-variant keys are rejected.
func TestMCP_CaseVariantAndDuplicateKeysRejected(t *testing.T) {
	p := allowlistPolicy(t)
	for name, body := range map[string]string{
		"Name after name":        `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all","Name":"read"}}`,
		"Name only":              `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"NAME":"read"}}`,
		"duplicate name":         `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all","name":"read"}}`,
		"Method after method":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"delete_all"}}`,
		"Method only":            `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"delete_all"}}`,
		"duplicate method":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping","params":{"name":"delete_all"}}`,
		"Params after params":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"},"Params":{"name":"read"}}`,
		"duplicate params":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"},"params":{"name":"read"}}`,
		"unicode fold of params": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_all\"},\"param\u017f\":{\"name\":\"read\"}}",
		"batch case variant":     `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all","Name":"read"}}]`,
		"escaped key duplicate":  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all","n\u0061me":"read"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := checkMCPBody(t, p, body, nil)
			requireMCPReject(t, err, http.StatusBadRequest)
		})
	}

	// Case variants of keys that do not drive the decision are left alone.
	res, err := checkMCPBody(t, p,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"Name":"x","name":"y"}}}`, nil)
	require.NoError(t, err)
	assert.False(t, res.Denied)
}

func TestMCP_MethodlessMessagesPass(t *testing.T) {
	p := allowlistPolicy(t)
	// Responses to server-initiated requests carry no method.
	res, err := checkMCPBody(t, p, `{"jsonrpc":"2.0","id":5,"result":{}}`, nil)
	require.NoError(t, err)
	assert.False(t, res.Denied)
}

func TestMCP_PassthroughPolicyDoesNotRejectOrTruncate(t *testing.T) {
	p, err := NewMCPToolPolicy(&MCPToolPolicyConfig{})
	require.NoError(t, err)

	res, err := checkMCPBody(t, p, "{not json", nil)
	require.NoError(t, err)
	assert.False(t, res.Denied)

	big := bytes.Repeat([]byte("x"), maxMCPBodySize+100)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	_, err = p.CheckRequest(req)
	require.NoError(t, err)
	got, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, len(big), len(got), "pass-through must forward the full body")
}

func newMCPGateway(t *testing.T, upstreamHits *atomic.Int32) *httptest.Server {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	access, err := NewAccessPolicy([]AccessRuleInput{{Action: "ALLOW", Method: "POST", Path: "/"}}, false)
	require.NoError(t, err)
	router := NewRouter(RouterConfig{Logger: airlocklog.NewLogger(io.Discard, "test", "")})
	router.AddRoute(&Route{
		PathPrefix: "/mcp", StripPrefix: "/mcp", Upstream: upstreamURL,
		Auth: auth.NewNoneAuth(), Access: access, MCPRules: allowlistPolicy(t),
	})
	gw := httptest.NewServer(router)
	t.Cleanup(gw.Close)
	return gw
}

func TestRouter_MCPRejectionsNeverReachUpstream(t *testing.T) {
	var hits atomic.Int32
	gw := newMCPGateway(t, &hits)

	call := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}`)
	oversized := append(append([]byte{}, call...), bytes.Repeat([]byte(" "), maxMCPBodySize)...)

	cases := []struct {
		name   string
		body   io.Reader
		header map[string]string
		want   int
	}{
		{"oversized content-length", bytes.NewReader(oversized), nil, http.StatusRequestEntityTooLarge},
		{"oversized chunked", struct{ io.Reader }{bytes.NewReader(oversized)}, nil, http.StatusRequestEntityTooLarge},
		{"gzip", bytes.NewReader(call), map[string]string{"Content-Encoding": "gzip"}, http.StatusUnsupportedMediaType},
		{"text/plain", bytes.NewReader(call), map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType},
		{"malformed", strings.NewReader(`{"method":"tools/call"`), nil, http.StatusBadRequest},
		{"case variant", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all","Name":"read"}}`), nil, http.StatusBadRequest},
		{"NaN id", strings.NewReader(`{"jsonrpc":"2.0","id":NaN,"method":"tools/call","params":{"name":"delete_all"}}`), nil, http.StatusBadRequest},
		{"denied", bytes.NewReader(call), map[string]string{"Content-Type": "Application/JSON; charset=utf-8"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := hits.Load()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.URL+"/mcp", tc.body)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			assert.Equal(t, tc.want, resp.StatusCode)
			assert.Equal(t, before, hits.Load(), "rejected request must not reach upstream")
		})
	}

	// A well-formed allowed call still goes through.
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}
