package proxy

import (
	"bytes"
	"io"
	"sort"
)

var redactedPlaceholder = []byte("[REDACTED]")

// prepareRedactTokens deduplicates, filters empty strings, and sorts
// the given secrets longest-first. Returns nil if no valid tokens remain.
//
// Equal-length tokens are ordered lexicographically so that the replacement
// order — and therefore the output — is deterministic for a given set.
func prepareRedactTokens(secrets []string) [][]byte {
	seen := make(map[string]struct{})
	tokens := make([][]byte, 0, len(secrets))
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		tokens = append(tokens, []byte(s))
	}
	if len(tokens) == 0 {
		return nil
	}
	sort.Slice(tokens, func(i, j int) bool {
		if len(tokens[i]) != len(tokens[j]) {
			return len(tokens[i]) > len(tokens[j])
		}
		return bytes.Compare(tokens[i], tokens[j]) < 0
	})
	return tokens
}

// redactAll replaces every occurrence of each token with the placeholder,
// longest token first, over a complete buffer. It is the reference definition
// of redaction; the streaming redactor reproduces it exactly for any chunking.
func redactAll(tokens [][]byte, body []byte) []byte {
	for _, tok := range tokens {
		body = bytes.ReplaceAll(body, tok, redactedPlaceholder)
	}
	return body
}

// tokenReplacer applies a single token's ReplaceAll to a stream delivered in
// arbitrary pieces. It replaces every complete occurrence it can see and holds
// back only the longest tail that is a proper prefix of the token, since that
// tail is the only part the next piece can turn into a match. Everything it
// returns is final, so the concatenated output equals ReplaceAll over the
// concatenated input regardless of how the input was split.
type tokenReplacer struct {
	tok  []byte
	held []byte
}

func (t *tokenReplacer) push(data []byte) []byte {
	if len(data) == 0 && len(t.held) == 0 {
		return nil
	}
	buf := make([]byte, 0, len(t.held)+len(data))
	buf = append(buf, t.held...)
	buf = append(buf, data...)

	out := make([]byte, 0, len(buf))
	i := 0
	for {
		idx := bytes.Index(buf[i:], t.tok)
		if idx < 0 {
			break
		}
		out = append(out, buf[i:i+idx]...)
		out = append(out, redactedPlaceholder...)
		i += idx + len(t.tok)
	}

	rest := buf[i:]
	k := tokenPrefixSuffixLen(rest, t.tok)
	out = append(out, rest[:len(rest)-k]...)
	t.held = append([]byte(nil), rest[len(rest)-k:]...)
	return out
}

// flush releases the held tail, which cannot contain a complete occurrence of
// this replacer's token.
func (t *tokenReplacer) flush() []byte {
	out := t.held
	t.held = nil
	return out
}

// tokenPrefixSuffixLen returns the length of the longest suffix of b that is a
// proper prefix of tok.
func tokenPrefixSuffixLen(b, tok []byte) int {
	k := min(len(tok)-1, len(b))
	for ; k > 0; k-- {
		if bytes.HasPrefix(tok, b[len(b)-k:]) {
			return k
		}
	}
	return 0
}

// streamRedactor replaces secrets in a stream delivered in arbitrary pieces.
// It is a cascade of one tokenReplacer per secret, longest secret first, which
// is the streaming form of redactAll: each stage's output is the next stage's
// input, so pushing a body in any number of pieces and then flushing produces
// exactly redactAll of that body.
type streamRedactor struct {
	stages []*tokenReplacer
}

func newStreamRedactor(tokens [][]byte) *streamRedactor {
	stages := make([]*tokenReplacer, 0, len(tokens))
	for _, tok := range tokens {
		stages = append(stages, &tokenReplacer{tok: tok})
	}
	return &streamRedactor{stages: stages}
}

func (s *streamRedactor) push(data []byte) []byte {
	for _, stage := range s.stages {
		data = stage.push(data)
	}
	return data
}

// flush drains every stage in order. A stage's held tail can still contain a
// shorter secret, so it is pushed through the stages behind it before that
// stage is drained in turn.
func (s *streamRedactor) flush() []byte {
	var out []byte
	for i, stage := range s.stages {
		data := stage.flush()
		for _, next := range s.stages[i+1:] {
			data = next.push(data)
		}
		out = append(out, data...)
	}
	return out
}

// redactingReader wraps an io.ReadCloser and replaces all occurrences of
// sensitive credential strings with "[REDACTED]" in a streaming fashion.
//
// Redaction state carries across reads, and only a tail that could still begin
// a secret is held back, so the output does not depend on where the upstream
// splits the body. Secrets are replaced longest-first so that "Bearer sk-abc"
// is replaced before "sk-abc" (preventing orphaned prefixes).
type redactingReader struct {
	inner   io.ReadCloser
	sr      *streamRedactor
	buf     []byte // scratch buffer for reading from inner
	out     []byte // buffered output that didn't fit in caller's p
	srcDone bool
}

// newRedactingReader wraps r so that any occurrence of the given secrets
// is replaced with [REDACTED]. If secrets is empty, r is returned as-is.
func newRedactingReader(r io.ReadCloser, secrets []string) io.ReadCloser {
	tokens := prepareRedactTokens(secrets)
	if tokens == nil {
		return r
	}
	return &redactingReader{
		inner: r,
		sr:    newStreamRedactor(tokens),
		buf:   make([]byte, 32*1024),
	}
}

func (r *redactingReader) Read(p []byte) (int, error) {
	// Serve any buffered output that didn't fit in the previous call.
	if len(r.out) > 0 {
		n := copy(p, r.out)
		r.out = r.out[n:]
		return n, nil
	}

	if r.srcDone {
		return 0, io.EOF
	}

	// Read new data from the underlying reader.
	n, readErr := r.inner.Read(r.buf)
	if readErr != nil && readErr != io.EOF {
		return 0, readErr
	}

	data := r.sr.push(r.buf[:n])
	if readErr == io.EOF {
		r.srcDone = true
		// The held tails are released only here, so no data is lost.
		data = append(data, r.sr.flush()...)
	}

	if len(data) == 0 {
		if r.srcDone {
			return 0, io.EOF
		}
		// Everything read so far could still begin a secret.
		return 0, nil
	}

	// Copy the safe portion to the caller's buffer.
	copied := copy(p, data)
	if copied < len(data) {
		// Didn't fit — buffer the rest for the next Read call.
		r.out = append([]byte(nil), data[copied:]...)
	}

	if r.srcDone && len(r.out) == 0 {
		return copied, io.EOF
	}
	return copied, nil
}

func (r *redactingReader) Close() error {
	return r.inner.Close()
}

// newSSERedactingReader wraps r for SSE streams. Any occurrence of secrets
// in event data is replaced with [REDACTED]. If secrets is empty, r is
// returned as-is.
//
// Redaction state carries across event batches and the safety flush, so a
// secret split by a flush is still caught. Only a tail that could be the
// start of a secret is held back; events end in "\n\n" and are normally
// delivered whole and immediately.
func newSSERedactingReader(r io.ReadCloser, secrets []string) io.ReadCloser {
	tokens := prepareRedactTokens(secrets)
	if tokens == nil {
		return r
	}
	sr := newStreamRedactor(tokens)
	er := newSSEEventReader(r, sr.push)
	er.final = sr.flush
	return er
}

// redactHeaderValues scans all response header values for the given secrets
// and replaces occurrences with [REDACTED]. Secrets are processed longest-first
// so that "Bearer sk-abc" is replaced before "sk-abc".
func redactHeaderValues(headers map[string][]string, secrets []string) {
	tokens := prepareRedactTokens(secrets)
	if tokens == nil {
		return
	}
	for name, vals := range headers {
		for i, v := range vals {
			headers[name][i] = string(redactAll(tokens, []byte(v)))
		}
	}
}
