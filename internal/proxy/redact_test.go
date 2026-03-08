package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedact_NoSecrets_Passthrough(t *testing.T) {
	body := io.NopCloser(strings.NewReader("hello world"))
	r := newRedactingReader(body, nil)
	// Should return the original reader, not a wrapper.
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(out))
}

func TestRedact_EmptySecrets_Passthrough(t *testing.T) {
	body := io.NopCloser(strings.NewReader("hello world"))
	r := newRedactingReader(body, []string{"", ""})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(out))
}

func TestRedact_SingleOccurrence(t *testing.T) {
	body := io.NopCloser(strings.NewReader(`{"auth": "Bearer sk-secret-123"}`))
	r := newRedactingReader(body, []string{"sk-secret-123"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret-123")
	assert.Contains(t, string(out), "[REDACTED]")
}

func TestRedact_MultipleOccurrences(t *testing.T) {
	body := io.NopCloser(strings.NewReader(`token=sk-abc, again=sk-abc`))
	r := newRedactingReader(body, []string{"sk-abc"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "token=[REDACTED], again=[REDACTED]", string(out))
}

func TestRedact_BothTokenAndHeaderValue(t *testing.T) {
	body := io.NopCloser(strings.NewReader(`"Authorization": "Bearer sk-secret-123"`))
	r := newRedactingReader(body, []string{"sk-secret-123", "Bearer sk-secret-123"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret-123")
	// The longer match "Bearer sk-secret-123" should be replaced as a unit.
	assert.Contains(t, string(out), "[REDACTED]")
}

func TestRedact_TokenSpanningChunkBoundary(t *testing.T) {
	// Use a tiny reader that returns a few bytes at a time to force the token
	// to span multiple Read calls.
	token := "SECRET-TOKEN-12345"
	// Place token in the middle of some text.
	data := "prefix-" + token + "-suffix"

	r := newRedactingReader(
		io.NopCloser(&tinyReader{data: []byte(data), chunkSize: 5}),
		[]string{token},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), token)
	assert.Contains(t, string(out), "[REDACTED]")
	assert.Contains(t, string(out), "prefix-")
	assert.Contains(t, string(out), "-suffix")
}

func TestRedact_TokenAtStart(t *testing.T) {
	body := io.NopCloser(strings.NewReader("sk-abc rest of body"))
	r := newRedactingReader(body, []string{"sk-abc"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "[REDACTED] rest of body", string(out))
}

func TestRedact_TokenAtEnd(t *testing.T) {
	body := io.NopCloser(strings.NewReader("body ends with sk-abc"))
	r := newRedactingReader(body, []string{"sk-abc"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "body ends with [REDACTED]", string(out))
}

func TestRedact_EmptyBody(t *testing.T) {
	body := io.NopCloser(strings.NewReader(""))
	r := newRedactingReader(body, []string{"token"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestRedact_NoMatch(t *testing.T) {
	original := "this body has no secrets"
	body := io.NopCloser(strings.NewReader(original))
	r := newRedactingReader(body, []string{"sk-not-here"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, original, string(out))
}

func TestRedact_SSEStream(t *testing.T) {
	// Simulate SSE events that include a token.
	events := `data: {"token": "sk-secret"}\n\ndata: {"token": "sk-secret"}\n\n`
	r := newRedactingReader(
		io.NopCloser(&tinyReader{data: []byte(events), chunkSize: 30}),
		[]string{"sk-secret"},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret")
	assert.Equal(t, 2, strings.Count(string(out), "[REDACTED]"))
}

func TestRedact_DuplicateSecrets(t *testing.T) {
	body := io.NopCloser(strings.NewReader("token is sk-abc here"))
	r := newRedactingReader(body, []string{"sk-abc", "sk-abc", "sk-abc"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "token is [REDACTED] here", string(out))
}

func TestRedact_ClosePropagatesToInner(t *testing.T) {
	inner := &trackingCloser{Reader: strings.NewReader("data")}
	r := newRedactingReader(inner, []string{"token"})
	_ = r.Close()
	assert.True(t, inner.closed)
}

func TestRedactHeaders_Basic(t *testing.T) {
	headers := map[string][]string{
		"X-Echo-Auth": {"Bearer sk-secret-123"},
		"Content-Type": {"application/json"},
	}
	redactHeaderValues(headers, []string{"sk-secret-123", "Bearer sk-secret-123"})
	assert.Equal(t, "[REDACTED]", headers["X-Echo-Auth"][0])
	assert.Equal(t, "application/json", headers["Content-Type"][0])
}

func TestRedactHeaders_NoMatch(t *testing.T) {
	headers := map[string][]string{
		"Server": {"nginx"},
	}
	redactHeaderValues(headers, []string{"sk-abc"})
	assert.Equal(t, "nginx", headers["Server"][0])
}

// --- Helpers ---

// tinyReader returns data in small fixed-size chunks to test cross-boundary behavior.
type tinyReader struct {
	data      []byte
	chunkSize int
	offset    int
}

func (r *tinyReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	end := r.offset + r.chunkSize
	if end > len(r.data) {
		end = len(r.data)
	}
	n := copy(p, r.data[r.offset:end])
	r.offset += n
	if r.offset >= len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

// trackingCloser wraps a Reader and records whether Close was called.
type trackingCloser struct {
	io.Reader
	closed bool
}

func (c *trackingCloser) Close() error {
	c.closed = true
	return nil
}

// =============================================================================
// SSE Redacting Reader Tests
// =============================================================================

func TestSSERedact_TokenInSingleEvent(t *testing.T) {
	data := "data: {\"token\": \"sk-secret\"}\n\ndata: {\"safe\": true}\n\n"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), []string{"sk-secret"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret")
	assert.Contains(t, string(out), "[REDACTED]")
	assert.Contains(t, string(out), `"safe": true`)
}

func TestSSERedact_TokenAcrossDataLines(t *testing.T) {
	// Token spans event: and data: lines within the same event.
	data := "event: message\ndata: key=sk-secret\n\n"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), []string{"sk-secret"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret")
	assert.Contains(t, string(out), "event: message")
	assert.Contains(t, string(out), "[REDACTED]")
}

func TestSSERedact_MultipleEventsWithToken(t *testing.T) {
	data := "data: {\"k\": \"sk-abc\"}\n\ndata: {\"k\": \"sk-abc\"}\n\ndata: {\"k\": \"safe\"}\n\n"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), []string{"sk-abc"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-abc")
	assert.Equal(t, 2, strings.Count(string(out), "[REDACTED]"))
	assert.Contains(t, string(out), "safe")
}

func TestSSERedact_NoToken_Passthrough(t *testing.T) {
	data := "data: hello\n\ndata: world\n\n"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), []string{"sk-not-here"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, data, string(out))
}

func TestSSERedact_TinyChunks(t *testing.T) {
	data := "data: {\"token\": \"sk-secret\"}\n\ndata: {\"safe\": true}\n\n"
	r := newSSERedactingReader(
		io.NopCloser(&tinyReader{data: []byte(data), chunkSize: 10}),
		[]string{"sk-secret"},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret")
	assert.Contains(t, string(out), "[REDACTED]")
	assert.Contains(t, string(out), `"safe": true`)
}

func TestSSERedact_PartialFinalEvent(t *testing.T) {
	// Stream ends without trailing \n\n.
	data := "data: {\"token\": \"sk-secret\"}\n\ndata: partial"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), []string{"sk-secret"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret")
	assert.Contains(t, string(out), "[REDACTED]")
	assert.Contains(t, string(out), "data: partial")
}

func TestSSERedact_CRLF_LineEndings(t *testing.T) {
	// \r\n line endings should be normalized to \n.
	data := "data: {\"token\": \"sk-secret\"}\r\n\r\ndata: safe\r\n\r\n"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), []string{"sk-secret"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret")
	assert.Contains(t, string(out), "[REDACTED]")
	assert.Contains(t, string(out), "data: safe")
	// Output should be normalized to \n.
	assert.NotContains(t, string(out), "\r")
}

func TestSSERedact_CRLF_StraddlesChunks(t *testing.T) {
	// \r at end of one chunk, \n at start of next — must NOT create spurious \n\n.
	// "data: hello\r\ndata: world\n\n" with chunk boundary after the \r.
	data := "data: hello\r\ndata: world\n\n"
	r := newSSERedactingReader(
		// chunkSize=12 puts the split right after "data: hello\r"
		io.NopCloser(&tinyReader{data: []byte(data), chunkSize: 12}),
		[]string{"not-present"},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	// Should be a single event with two data fields, not split into two events.
	normalized := "data: hello\ndata: world\n\n"
	assert.Equal(t, normalized, string(out))
}

func TestSSERedact_CR_LineEndings(t *testing.T) {
	// Standalone \r (old Mac style) should also be normalized.
	data := "data: token=sk-abc\r\rdata: safe\r\r"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), []string{"sk-abc"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-abc")
	assert.Contains(t, string(out), "[REDACTED]")
}

func TestSSERedact_EmptyStream(t *testing.T) {
	r := newSSERedactingReader(io.NopCloser(strings.NewReader("")), []string{"token"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestSSERedact_NoSecrets_Passthrough(t *testing.T) {
	data := "data: hello\n\n"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), nil)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, data, string(out))
}

func TestSSERedact_DuplicateSecrets(t *testing.T) {
	data := "data: sk-abc\n\n"
	r := newSSERedactingReader(io.NopCloser(strings.NewReader(data)), []string{"sk-abc", "sk-abc", "sk-abc"})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "data: [REDACTED]\n\n", string(out))
}

func TestSSERedact_ClosePropagatesToInner(t *testing.T) {
	inner := &trackingCloser{Reader: strings.NewReader("data")}
	r := newSSERedactingReader(inner, []string{"token"})
	_ = r.Close()
	assert.True(t, inner.closed)
}

func TestSSERedact_BothTokenAndBearer(t *testing.T) {
	data := "data: {\"auth\": \"Bearer sk-secret-123\"}\n\n"
	r := newSSERedactingReader(
		io.NopCloser(strings.NewReader(data)),
		[]string{"sk-secret-123", "Bearer sk-secret-123"},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sk-secret-123")
	assert.Contains(t, string(out), "[REDACTED]")
}

func TestRedact_LargeBody(t *testing.T) {
	// 1MB body with a token buried in the middle.
	token := "sk-secret-key-to-redact"
	prefix := bytes.Repeat([]byte("A"), 512*1024)
	suffix := bytes.Repeat([]byte("B"), 512*1024)
	data := append(append(prefix, []byte(token)...), suffix...)

	r := newRedactingReader(io.NopCloser(bytes.NewReader(data)), []string{token})
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), token)
	assert.Contains(t, string(out), "[REDACTED]")
}
