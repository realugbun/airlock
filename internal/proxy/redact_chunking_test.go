package proxy

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// splitReader delivers a body in a fixed sequence of chunks, one per Read, so
// a test can choose exactly where the upstream splits it.
type splitReader struct {
	chunks [][]byte
	closed bool
}

func newSplitReader(body []byte, cuts ...int) *splitReader {
	r := &splitReader{}
	prev := 0
	for _, c := range cuts {
		if c <= prev || c >= len(body) {
			continue
		}
		r.chunks = append(r.chunks, body[prev:c])
		prev = c
	}
	if prev < len(body) {
		r.chunks = append(r.chunks, body[prev:])
	}
	return r
}

func (r *splitReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func (r *splitReader) Close() error {
	r.closed = true
	return nil
}

// oneShotRedact is the reference redaction of a whole body: every secret
// replaced everywhere, longest secret first.
func oneShotRedact(secrets []string, body []byte) []byte {
	tokens := prepareRedactTokens(secrets)
	if tokens == nil {
		return body
	}
	return redactAll(tokens, append([]byte(nil), body...))
}

// Overlapping secrets where one is a prefix of the other: replacing the
// shorter one as soon as it is seen would commit to the wrong match, making
// the output depend on where the upstream split the body.
func TestRedact_ChunkBoundaryDoesNotChangeOutput(t *testing.T) {
	secrets := []string{"aa", "aaa"}
	const body = "aaa"

	whole, err := io.ReadAll(newRedactingReader(newSplitReader([]byte(body)), secrets))
	require.NoError(t, err)
	require.Equal(t, "[REDACTED]", string(whole))

	split, err := io.ReadAll(newRedactingReader(newSplitReader([]byte(body), 2), secrets))
	require.NoError(t, err)
	require.Equal(t, string(whole), string(split), `body "aaa" split as "aa"|"a"`)
	require.Equal(t, string(oneShotRedact(secrets, []byte(body))), string(split))
}

// Every split of a body containing the bare token, the prefixed token, and
// decoy prefixes of both.
func TestRedact_EverySplitOfOverlappingSecrets(t *testing.T) {
	secrets := []string{"tok", "Bearer tok"}
	body := []byte("a Bearer tok b tok c Bear tok d Bearer to e")
	want := string(oneShotRedact(secrets, body))
	require.NotContains(t, want, "tok ")

	for i := 1; i < len(body); i++ {
		got, err := io.ReadAll(newRedactingReader(newSplitReader(body, i), secrets))
		require.NoError(t, err)
		require.Equal(t, want, string(got), "split at %d", i)

		gotSSE, err := io.ReadAll(newSSERedactingReader(newSplitReader(body, i), secrets))
		require.NoError(t, err)
		require.Equal(t, want, string(gotSSE), "SSE split at %d", i)
	}
}

// Both redactors must reproduce the one-shot redaction for every redaction set
// of the shape the auth providers produce — the bare token T and the injected
// header value P+T — over every single and double split of short bodies.
func TestRedact_StreamedEqualsOneShot_AllSplits(t *testing.T) {
	const alphabet = "ab"
	const bodyAlphabet = "ab\n" // \n so SSE event boundaries occur in the bodies

	tokens := wordsUpTo(alphabet, 1, 3)
	prefixes := wordsUpTo(alphabet, 0, 2)
	bodies := wordsUpTo(bodyAlphabet, 0, 4)

	checked := 0
	for _, tok := range tokens {
		for _, prefix := range prefixes {
			secrets := []string{tok, prefix + tok}
			for _, b := range bodies {
				body := []byte(b)
				want := string(oneShotRedact(secrets, body))
				for _, cuts := range splitPlans(len(body)) {
					got, err := io.ReadAll(newRedactingReader(newSplitReader(body, cuts...), secrets))
					require.NoError(t, err)
					require.Equal(t, want, string(got),
						"secrets %q body %q cuts %v", secrets, body, cuts)

					gotSSE, err := io.ReadAll(newSSERedactingReader(newSplitReader(body, cuts...), secrets))
					require.NoError(t, err)
					require.Equal(t, want, string(gotSSE),
						"SSE secrets %q body %q cuts %v", secrets, body, cuts)
					checked += 2
				}
			}
		}
	}
	t.Logf("compared %d streamed redactions against one-shot redaction", checked)
}

// Small caller buffers and one-byte upstream chunks must not change the output
// or lose data.
func TestRedact_SmallReadsAndOneByteChunks(t *testing.T) {
	secrets := []string{"sk-9", "Bearer sk-9"}
	body := []byte("x Bearer sk-9 y sk-9 z sk- w")
	want := string(oneShotRedact(secrets, body))

	cuts := make([]int, 0, len(body))
	for i := 1; i < len(body); i++ {
		cuts = append(cuts, i)
	}
	r := newRedactingReader(newSplitReader(body, cuts...), secrets)

	var got []byte
	p := make([]byte, 3)
	for {
		n, err := r.Read(p)
		got = append(got, p[:n]...)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	require.Equal(t, want, string(got))
}

// wordsUpTo returns every string over alphabet with length in [minLen, maxLen].
func wordsUpTo(alphabet string, minLen, maxLen int) []string {
	words := []string{""}
	var out []string
	if minLen == 0 {
		out = append(out, "")
	}
	for length := 1; length <= maxLen; length++ {
		next := make([]string, 0, len(words)*len(alphabet))
		for _, w := range words {
			for _, c := range alphabet {
				next = append(next, w+string(c))
			}
		}
		words = next
		if length >= minLen {
			out = append(out, words...)
		}
	}
	return out
}

// splitPlans returns the cut positions for no split, every single split and
// every double split of a body of length n.
func splitPlans(n int) [][]int {
	plans := [][]int{{}}
	for i := 1; i < n; i++ {
		plans = append(plans, []int{i})
		for j := i + 1; j < n; j++ {
			plans = append(plans, []int{i, j})
		}
	}
	return plans
}

// The held tail is released at EOF even when it is the whole body.
func TestRedact_HeldTailReleasedAtEOF(t *testing.T) {
	secrets := []string{"secret-value"}
	got, err := io.ReadAll(newRedactingReader(newSplitReader([]byte("secr"), 2), secrets))
	require.NoError(t, err)
	require.Equal(t, "secr", string(got))
}

// A large body still redacts and its output does not depend on the 32 KiB
// read buffer boundary.
func TestRedact_SecretAcrossReadBufferBoundary(t *testing.T) {
	secrets := []string{"sk-boundary", "Bearer sk-boundary"}
	const bufSize = 32 * 1024
	for off := bufSize - len("Bearer sk-boundary") - 1; off <= bufSize+1; off++ {
		body := append(bytes.Repeat([]byte("A"), off), "Bearer sk-boundary tail"...)
		got, err := io.ReadAll(newRedactingReader(newSplitReader(body), secrets))
		require.NoError(t, err)
		require.Equal(t, string(oneShotRedact(secrets, body)), string(got), "offset %d", off)
		require.NotContains(t, string(got), "sk-boundary")
	}
}
