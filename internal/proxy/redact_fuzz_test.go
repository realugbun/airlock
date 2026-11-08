package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// FuzzRedactStreaming varies the secrets, the body and the points where the
// body is split, and checks the two invariants the redactors must hold:
//
//  1. Streamed output equals the one-shot redaction of the whole body, so the
//     agent cannot change what it sees by making the upstream chunk differently.
//  2. No secret survives in the output.
//
// Invariant 2 is only claimed for secrets that contain neither '[' nor ']'
// (a bracketed credential can be re-formed by the placeholder, which is why
// the router refuses one) and that are not substrings of the constant
// placeholder text (a secret such as "RED" "appears" in every "[REDACTED]"
// while revealing nothing).
func FuzzRedactStreaming(f *testing.F) {
	f.Add("aa", "aaa", "aaa", uint8(2), uint8(0))
	f.Add("tok", "Bearer tok", "x Bearer tok y tok z Bear tok", uint8(8), uint8(20))
	f.Add("ba", "aba", "baba", uint8(1), uint8(3))
	f.Add("XY", "]Z!", "XYZ!", uint8(2), uint8(0))
	f.Add("sk-9", "", "data: sk-9\n\ndata: sk-\n\n", uint8(7), uint8(12))
	f.Add("a", "ab", "abab\r\nabba", uint8(1), uint8(6))
	f.Add("secret", "Bearer secret", "", uint8(0), uint8(0))

	f.Fuzz(func(t *testing.T, s1, s2, body string, cut1, cut2 uint8) {
		if len(s1) > 64 || len(s2) > 64 || len(body) > 4096 {
			return
		}
		secrets := []string{s1, s2}
		tokens := prepareRedactTokens(secrets)
		if tokens == nil {
			return
		}

		cuts := splitCuts(len(body), cut1, cut2)

		// 1. Streaming must reproduce the one-shot redaction exactly.
		want := oneShotRedact(secrets, []byte(body))
		got, err := io.ReadAll(newRedactingReader(newSplitReader([]byte(body), cuts...), secrets))
		if err != nil {
			t.Fatalf("redacting reader: %v", err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("streamed output differs from one-shot output\nsecrets %q\nbody %q\ncuts %v\none-shot %q\nstreamed %q",
				secrets, body, cuts, want, got)
		}

		// The SSE reader normalizes line endings, so its reference is the same
		// stream delivered in a single read.
		wantSSE, err := io.ReadAll(newSSERedactingReader(newSplitReader([]byte(body)), secrets))
		if err != nil {
			t.Fatalf("SSE redacting reader (one read): %v", err)
		}
		gotSSE, err := io.ReadAll(newSSERedactingReader(newSplitReader([]byte(body), cuts...), secrets))
		if err != nil {
			t.Fatalf("SSE redacting reader: %v", err)
		}
		if !bytes.Equal(wantSSE, gotSSE) {
			t.Fatalf("streamed SSE output differs from one-shot SSE output\nsecrets %q\nbody %q\ncuts %v\none-shot %q\nstreamed %q",
				secrets, body, cuts, wantSSE, gotSSE)
		}

		// 2. No secret survives redaction.
		if !redactionSafe(secrets) {
			return
		}
		for _, s := range secrets {
			if s == "" || bytes.Contains(redactedPlaceholder, []byte(s)) {
				continue
			}
			for _, out := range [][]byte{got, gotSSE} {
				if bytes.Contains(out, []byte(s)) {
					t.Fatalf("secret %q survived redaction\nbody %q\ncuts %v\noutput %q",
						s, body, cuts, out)
				}
			}
		}
	})
}

// splitCuts maps two fuzz bytes onto ascending cut positions inside a body of
// length n.
func splitCuts(n int, cut1, cut2 uint8) []int {
	if n < 2 {
		return nil
	}
	a := int(cut1)%(n-1) + 1
	b := int(cut2)%(n-1) + 1
	if a > b {
		a, b = b, a
	}
	if a == b {
		return []int{a}
	}
	return []int{a, b}
}

// Headers go through the same replacement as bodies, so the same secrets are
// unsafe there. redactHeaderValues is only reached for a redaction set the
// router already accepted.
func FuzzRedactHeaderValues(f *testing.F) {
	f.Add("tok", "Bearer tok", "X-Echo", "value: Bearer tok")
	f.Add("aa", "aaa", "X-Echo", "aaaa")

	f.Fuzz(func(t *testing.T, s1, s2, name, value string) {
		if len(s1) > 64 || len(s2) > 64 || len(value) > 4096 || !strings.HasPrefix(name, "X-") {
			return
		}
		secrets := []string{s1, s2}
		if !redactionSafe(secrets) {
			return
		}
		headers := map[string][]string{name: {value}}
		redactHeaderValues(headers, secrets)
		out := headers[name][0]
		if out != string(oneShotRedact(secrets, []byte(value))) {
			t.Fatalf("header redaction differs from body redaction: %q vs %q",
				out, oneShotRedact(secrets, []byte(value)))
		}
		for _, s := range secrets {
			if s == "" || strings.Contains(string(redactedPlaceholder), s) {
				continue
			}
			if strings.Contains(out, s) {
				t.Fatalf("secret %q survived header redaction: %q", s, out)
			}
		}
	})
}
