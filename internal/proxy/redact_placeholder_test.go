package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A credential that is a substring of the placeholder text is refused before
// the upstream is contacted, the same way a bracketed one is. "DAC" and "ACT"
// are the middle three letters of "[REDACTED]"; "" and the whole placeholder
// are the degenerate ends of the same condition.
func TestRouter_PlaceholderSubstringCredentialRefused(t *testing.T) {
	for _, token := range []string{"DAC", "ACT", "RED", "ED", "R", "REDACTED", "[REDACTED]", ""} {
		name := token
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			var upstreamHits atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				_, _ = w.Write([]byte("should never be reached"))
			}))
			defer upstream.Close()

			var logs bytes.Buffer
			gw := httptest.NewServer(newRedactRouterWithLog(t, upstream, &bracketAuth{token: token}, &logs))
			defer gw.Close()

			resp, err := http.Get(gw.URL + "/u/x")
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			assert.GreaterOrEqual(t, resp.StatusCode, 500, "must fail closed with a 5xx")
			assert.Less(t, resp.StatusCode, 600)
			assert.Equal(t, int64(0), upstreamHits.Load(), "upstream must receive nothing")
			assert.NotContains(t, string(body), "should never be reached")

			logged := logs.String()
			assert.Contains(t, logged, "credential cannot be redacted")
			assert.Contains(t, logged, "/u", "the log must name the route")
			if token != "" {
				assert.NotContains(t, logged, `"`+token+`"`,
					"the log must not contain the credential value")
			}
		})
	}
}

// Without the substring check such a credential reaches the upstream and the
// redacted response still spells it: the whole point of refusing it. This
// documents the leak the check closes.
func TestRedact_PlaceholderSubstringAppearsInOutput(t *testing.T) {
	// Redacting "DAC" out of a body that mentions a token leaves the
	// placeholder, which contains "DAC" itself.
	out := oneShotRedact([]string{"DAC"}, []byte("value=DAC"))
	require.Equal(t, "value=[REDACTED]", string(out))
	require.Contains(t, string(out), "DAC",
		"the placeholder text spells the credential")
	require.False(t, redactionSafe([]string{"DAC"}),
		"which is why the credential is refused")

	// The same for the empty credential: every placeholder contains it, and
	// prepareRedactTokens would silently drop it, so the request is refused
	// rather than forwarded with a credential that is not redacted at all.
	require.False(t, redactionSafe([]string{""}))
	require.Nil(t, prepareRedactTokens([]string{""}))
}
