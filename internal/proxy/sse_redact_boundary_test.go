package proxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every placement of each secret around the 1 MiB safety flush.
func TestSSERedaction_SafetyFlushEverySplitPosition(t *testing.T) {
	secrets := []string{"tok-abcdef", "Bearer tok-abcdef"}
	for _, secret := range secrets {
		for off := sseMaxEventBuf - len(secret) - 2; off <= sseMaxEventBuf+2; off++ {
			data := make([]byte, 0, off+len(secret)+2)
			data = append(data, bytes.Repeat([]byte("A"), off)...)
			data = append(data, secret...)
			data = append(data, "\n\n"...)

			out, err := io.ReadAll(newSSERedactingReader(io.NopCloser(bytes.NewReader(data)), secrets))
			require.NoError(t, err)
			require.False(t, bytes.Contains(out, []byte("tok-abcdef")), "secret %q leaked at offset %d", secret, off)
			require.Len(t, out, off+len("[REDACTED]\n\n"), "offset %d", off)
			require.True(t, bytes.HasSuffix(out, []byte("A[REDACTED]\n\n")), "offset %d", off)
		}
	}
}

// Overlapping secrets: the prefixed header value must be redacted as a whole
// even when the flush splits it, and the bare token on its own still is.
func TestSSERedaction_OverlappingSecretsAcrossFlush(t *testing.T) {
	secrets := []string{"token", "Bearer token"}
	full := "Bearer token"
	for split := 1; split < len(full); split++ {
		pad := sseMaxEventBuf - split
		data := strings.Repeat("A", pad) + full + " and token\n\n"
		out, err := io.ReadAll(newSSERedactingReader(io.NopCloser(strings.NewReader(data)), secrets))
		require.NoError(t, err)
		got := string(out[pad:])
		assert.Equal(t, "[REDACTED] and [REDACTED]\n\n", got, "split at %d", split)
	}
}

// A tail that looks like the start of a secret is released at EOF and on a
// read error, so no data is lost.
func TestSSERedaction_HeldTailFlushedAtEOFAndError(t *testing.T) {
	secrets := []string{"secret-value"}

	out, err := io.ReadAll(newSSERedactingReader(io.NopCloser(strings.NewReader("data: partial secr")), secrets))
	require.NoError(t, err)
	assert.Equal(t, "data: partial secr", string(out))

	boom := errors.New("upstream reset")
	r := newSSERedactingReader(io.NopCloser(io.MultiReader(
		strings.NewReader(strings.Repeat("A", sseMaxEventBuf-4)+"secr"),
		iotest.ErrReader(boom),
	)), secrets)
	out, err = io.ReadAll(r)
	require.ErrorIs(t, err, boom)
	assert.True(t, bytes.HasSuffix(out, []byte("Asecr")))
	assert.Len(t, out, sseMaxEventBuf)
}

// Small reads and one-byte upstream chunks still redact and preserve data.
func TestSSERedaction_SmallChunksAndSmallReads(t *testing.T) {
	secrets := []string{"sk-123", "Bearer sk-123"}
	in := "data: Bearer sk-123\r\n\r\ndata: x sk-123 y\n\ndata: sk-12"
	r := newSSERedactingReader(io.NopCloser(iotest.OneByteReader(strings.NewReader(in))), secrets)
	out, err := io.ReadAll(iotest.OneByteReader(r))
	require.NoError(t, err)
	assert.Equal(t, "data: [REDACTED]\n\ndata: x [REDACTED] y\n\ndata: sk-12", string(out))
}

// Complete events are not delayed by the hold-back.
func TestSSERedaction_CompleteEventDeliveredImmediately(t *testing.T) {
	pr, pw := io.Pipe()
	r := newSSERedactingReader(pr, []string{"data-secret"})
	go func() { _, _ = pw.Write([]byte("data: hello\n\n")) }()

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := r.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case s := <-got:
		assert.Equal(t, "data: hello\n\n", s)
	case <-time.After(2 * time.Second):
		t.Fatal("complete event was held back")
	}
	_ = pw.Close()
}
