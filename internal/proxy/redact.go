package proxy

import (
	"bytes"
	"io"
	"sort"
	"strings"
)

var redactedPlaceholder = []byte("[REDACTED]")

// prepareRedactTokens deduplicates, filters empty strings, and sorts
// the given secrets longest-first. Returns nil if no valid tokens remain.
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
		return len(tokens[i]) > len(tokens[j])
	})
	return tokens
}

// redactingReader wraps an io.ReadCloser and replaces all occurrences of
// sensitive credential strings with "[REDACTED]" in a streaming fashion.
//
// It uses a carry buffer of maxTokenLen-1 bytes to handle tokens that span
// chunk boundaries. Tokens are sorted longest-first so that "Bearer sk-abc"
// is replaced before "sk-abc" (preventing orphaned prefixes).
type redactingReader struct {
	inner   io.ReadCloser
	tokens  [][]byte // sorted longest-first
	carry   []byte   // leftover bytes from previous read
	maxLen  int      // length of longest token
	buf     []byte   // scratch buffer for reading from inner
	out     []byte   // buffered output that didn't fit in caller's p
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
		inner:  r,
		tokens: tokens,
		maxLen: len(tokens[0]), // tokens sorted longest-first
		buf:    make([]byte, 32*1024),
	}
}

func (r *redactingReader) Read(p []byte) (int, error) {
	// Serve any buffered output that didn't fit in the previous call.
	if len(r.out) > 0 {
		n := copy(p, r.out)
		r.out = r.out[n:]
		return n, nil
	}

	if r.srcDone && len(r.carry) == 0 {
		return 0, io.EOF
	}

	// Read new data from the underlying reader.
	var n int
	var readErr error
	if !r.srcDone {
		n, readErr = r.inner.Read(r.buf)
		if readErr != nil && readErr != io.EOF {
			return 0, readErr
		}
		if readErr == io.EOF {
			r.srcDone = true
		}
	}

	// Combine carry + new data.
	combined := make([]byte, len(r.carry)+n)
	copy(combined, r.carry)
	copy(combined[len(r.carry):], r.buf[:n])
	r.carry = nil

	// Replace all token occurrences.
	for _, tok := range r.tokens {
		combined = bytes.ReplaceAll(combined, tok, redactedPlaceholder)
	}

	// If the source is not done, hold back the last maxLen-1 bytes as carry
	// because a token could straddle the chunk boundary.
	if !r.srcDone {
		if len(combined) >= r.maxLen {
			splitAt := len(combined) - (r.maxLen - 1)
			r.carry = make([]byte, len(combined)-splitAt)
			copy(r.carry, combined[splitAt:])
			combined = combined[:splitAt]
		} else {
			// Not enough data to flush anything yet; carry everything.
			r.carry = combined
			return 0, nil
		}
	}

	// Copy the safe portion to the caller's buffer.
	copied := copy(p, combined)
	if copied < len(combined) {
		// Didn't fit — buffer the rest for the next Read call.
		r.out = make([]byte, len(combined)-copied)
		copy(r.out, combined[copied:])
	}

	if r.srcDone && len(r.out) == 0 && len(r.carry) == 0 {
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
func newSSERedactingReader(r io.ReadCloser, secrets []string) io.ReadCloser {
	tokens := prepareRedactTokens(secrets)
	if tokens == nil {
		return r
	}
	return newSSEEventReader(r, func(data []byte) []byte {
		for _, tok := range tokens {
			data = bytes.ReplaceAll(data, tok, redactedPlaceholder)
		}
		return data
	})
}

// redactHeaderValues scans all response header values for the given secrets
// and replaces occurrences with [REDACTED]. Secrets are processed longest-first
// so that "Bearer sk-abc" is replaced before "sk-abc".
func redactHeaderValues(headers map[string][]string, secrets []string) {
	// Sort longest-first to match the body reader behavior.
	sorted := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if s != "" {
			sorted = append(sorted, s)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})

	for name, vals := range headers {
		for i, v := range vals {
			for _, secret := range sorted {
				v = strings.ReplaceAll(v, secret, "[REDACTED]")
			}
			headers[name][i] = v
		}
	}
}
