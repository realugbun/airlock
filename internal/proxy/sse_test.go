package proxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSEEventReader_IdentityTransform(t *testing.T) {
	data := "data: hello\n\ndata: world\n\n"
	r := newSSEEventReader(
		io.NopCloser(strings.NewReader(data)),
		func(d []byte) []byte { return d },
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, data, string(out))
}

func TestSSEEventReader_TransformApplied(t *testing.T) {
	data := "data: secret\n\ndata: safe\n\n"
	r := newSSEEventReader(
		io.NopCloser(strings.NewReader(data)),
		func(d []byte) []byte {
			return bytes.ReplaceAll(d, []byte("secret"), []byte("HIDDEN"))
		},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Contains(t, string(out), "HIDDEN")
	assert.NotContains(t, string(out), "secret")
	assert.Contains(t, string(out), "safe")
}

func TestSSEEventReader_CRLFNormalization(t *testing.T) {
	data := "data: hello\r\n\r\ndata: world\r\n\r\n"
	r := newSSEEventReader(
		io.NopCloser(strings.NewReader(data)),
		func(d []byte) []byte { return d },
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "\r")
	assert.Equal(t, "data: hello\n\ndata: world\n\n", string(out))
}

func TestSSEEventReader_CRNormalization(t *testing.T) {
	// Standalone \r (old Mac) normalized to \n.
	data := "data: hello\r\rdata: world\r\r"
	r := newSSEEventReader(
		io.NopCloser(strings.NewReader(data)),
		func(d []byte) []byte { return d },
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "\r")
	assert.Equal(t, "data: hello\n\ndata: world\n\n", string(out))
}

func TestSSEEventReader_BoundarySplitting(t *testing.T) {
	// Two events: transform should be called once for each batch
	// containing complete events up to the last \n\n.
	var calls int
	data := "data: first\n\ndata: second\n\n"
	r := newSSEEventReader(
		io.NopCloser(strings.NewReader(data)),
		func(d []byte) []byte {
			calls++
			return d
		},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, data, string(out))
	assert.GreaterOrEqual(t, calls, 1) // at least one transform call
}

func TestSSEEventReader_CrossChunkCRLF(t *testing.T) {
	// \r at end of one chunk, \n at start of next — must NOT create spurious \n\n.
	data := "data: hello\r\ndata: world\n\n"
	r := newSSEEventReader(
		// chunkSize=12 puts the split right after "data: hello\r"
		io.NopCloser(&tinyReader{data: []byte(data), chunkSize: 12}),
		func(d []byte) []byte { return d },
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	normalized := "data: hello\ndata: world\n\n"
	assert.Equal(t, normalized, string(out))
}

func TestSSEEventReader_SafetyValveFlush(t *testing.T) {
	// Create data larger than sseMaxEventBuf without any \n\n boundary.
	bigData := bytes.Repeat([]byte("x"), sseMaxEventBuf+100)
	var transformCalled bool
	r := newSSEEventReader(
		io.NopCloser(bytes.NewReader(bigData)),
		func(d []byte) []byte {
			transformCalled = true
			return d
		},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.True(t, transformCalled, "transform should be called via safety valve")
	assert.Equal(t, bigData, out)
}

func TestSSEEventReader_EOFFlushIncomplete(t *testing.T) {
	// Stream ends without trailing \n\n — remaining data should be flushed.
	data := "data: first\n\ndata: partial"
	r := newSSEEventReader(
		io.NopCloser(strings.NewReader(data)),
		func(d []byte) []byte {
			return bytes.ReplaceAll(d, []byte("partial"), []byte("FLUSHED"))
		},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Contains(t, string(out), "data: first\n\n")
	assert.Contains(t, string(out), "FLUSHED")
	assert.NotContains(t, string(out), "partial")
}

func TestSSEEventReader_SmallCallerBuffer(t *testing.T) {
	data := "data: hello world\n\n"
	r := newSSEEventReader(
		io.NopCloser(strings.NewReader(data)),
		func(d []byte) []byte { return d },
	)

	// Read byte by byte to exercise the output overflow buffer.
	var result bytes.Buffer
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	assert.Equal(t, data, result.String())
}

// errReader returns err after delivering data.
type errReader struct {
	data []byte
	err  error
	pos  int
	sent bool
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.pos < len(r.data) {
		n := copy(p, r.data[r.pos:])
		r.pos += n
		if r.pos >= len(r.data) && !r.sent {
			r.sent = true
			return n, r.err
		}
		return n, nil
	}
	return 0, r.err
}

func (r *errReader) Close() error { return nil }

func TestSSEEventReader_NonEOFErrorPropagation(t *testing.T) {
	testErr := errors.New("network failure")
	r := newSSEEventReader(
		&errReader{data: []byte("data: hello"), err: testErr},
		func(d []byte) []byte { return d },
	)

	out, err := io.ReadAll(r)
	assert.ErrorIs(t, err, testErr)
	// Buffered data should still be flushed.
	assert.Contains(t, string(out), "data: hello")
}

func TestSSEEventReader_EmptyStream(t *testing.T) {
	r := newSSEEventReader(
		io.NopCloser(strings.NewReader("")),
		func(d []byte) []byte { return d },
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestSSEEventReader_ClosePropagatesToInner(t *testing.T) {
	inner := &trackingCloser{Reader: strings.NewReader("data")}
	r := newSSEEventReader(inner, func(d []byte) []byte { return d })
	_ = r.Close()
	assert.True(t, inner.closed)
}

func TestSSEEventReader_TinyChunks(t *testing.T) {
	data := "data: {\"token\": \"secret\"}\n\ndata: {\"safe\": true}\n\n"
	r := newSSEEventReader(
		io.NopCloser(&tinyReader{data: []byte(data), chunkSize: 7}),
		func(d []byte) []byte {
			return bytes.ReplaceAll(d, []byte("secret"), []byte("REDACTED"))
		},
	)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "secret")
	assert.Contains(t, string(out), "REDACTED")
	assert.Contains(t, string(out), `"safe": true`)
}
