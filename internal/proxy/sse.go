package proxy

import (
	"bytes"
	"io"
)

// sseMaxEventBuf is the safety valve: if buf exceeds this without a \n\n
// boundary, flush with the transform anyway to prevent unbounded memory growth.
const sseMaxEventBuf = 1 << 20 // 1 MB

var eventBoundary = []byte("\n\n")

// sseEventReader wraps an io.ReadCloser delivering text/event-stream data
// and applies a transform function to each batch of complete SSE events.
//
// Events are buffered until a \n\n boundary is found, transformed as a unit,
// and flushed immediately. Line endings are normalized per the WHATWG SSE spec:
// \r\n → \n, standalone \r → \n. A prevCR flag handles \r\n pairs that
// straddle chunk boundaries.
type sseEventReader struct {
	inner     io.ReadCloser
	transform func([]byte) []byte // applied to each batch of complete events
	buf       []byte              // accumulated data awaiting \n\n boundary
	out       []byte              // transformed output ready to deliver
	readBuf   []byte              // scratch buffer for inner.Read
	prevCR    bool                // last byte appended was \r (for \r\n normalization)
	srcDone   bool
}

// newSSEEventReader creates an sseEventReader that applies transform to each
// batch of complete SSE events delimited by \n\n.
func newSSEEventReader(r io.ReadCloser, transform func([]byte) []byte) *sseEventReader {
	return &sseEventReader{
		inner:     r,
		transform: transform,
		readBuf:   make([]byte, 32*1024),
	}
}

func (r *sseEventReader) Read(p []byte) (int, error) {
	// Serve any buffered transformed output first.
	if len(r.out) > 0 {
		n := copy(p, r.out)
		r.out = r.out[n:]
		return n, nil
	}

	for {
		// If source is done, flush any remaining buffered data.
		if r.srcDone {
			if len(r.buf) == 0 {
				return 0, io.EOF
			}
			transformed := r.transform(r.buf)
			r.buf = nil
			n := copy(p, transformed)
			if n < len(transformed) {
				r.out = make([]byte, len(transformed)-n)
				copy(r.out, transformed[n:])
			}
			return n, io.EOF
		}

		// Read from inner (blocks until data arrives).
		n, err := r.inner.Read(r.readBuf)
		if n > 0 {
			r.appendNormalized(r.readBuf[:n])
		}
		if err != nil && err != io.EOF {
			// Non-EOF error: flush buf and propagate.
			if len(r.buf) > 0 {
				transformed := r.transform(r.buf)
				r.buf = nil
				n := copy(p, transformed)
				if n < len(transformed) {
					r.out = make([]byte, len(transformed)-n)
					copy(r.out, transformed[n:])
				}
				return n, err
			}
			return 0, err
		}
		if err == io.EOF {
			r.srcDone = true
		}

		// Check for complete events: find the last \n\n boundary.
		if idx := bytes.LastIndex(r.buf, eventBoundary); idx >= 0 {
			splitAt := idx + 2
			events := make([]byte, splitAt)
			copy(events, r.buf[:splitAt])
			remaining := r.buf[splitAt:]
			r.buf = make([]byte, len(remaining))
			copy(r.buf, remaining)

			transformed := r.transform(events)
			n := copy(p, transformed)
			if n < len(transformed) {
				r.out = make([]byte, len(transformed)-n)
				copy(r.out, transformed[n:])
			}
			return n, nil
		}

		// Safety valve: flush if buffer exceeds limit without \n\n.
		if len(r.buf) >= sseMaxEventBuf {
			transformed := r.transform(r.buf)
			r.buf = nil
			n := copy(p, transformed)
			if n < len(transformed) {
				r.out = make([]byte, len(transformed)-n)
				copy(r.out, transformed[n:])
			}
			return n, nil
		}

		// If source is done but no \n\n found, loop will handle flush.
		if r.srcDone {
			continue
		}
		// Otherwise, loop to read more from inner.
	}
}

// appendNormalized appends data to buf, normalizing line endings per the
// WHATWG SSE spec: \r\n → \n, standalone \r → \n. The prevCR flag handles
// \r\n pairs that straddle chunk boundaries.
func (r *sseEventReader) appendNormalized(data []byte) {
	for _, b := range data {
		switch {
		case b == '\r':
			r.buf = append(r.buf, '\n')
			r.prevCR = true
		case b == '\n' && r.prevCR:
			// Second half of \r\n — already emitted \n for the \r.
			r.prevCR = false
		default:
			r.prevCR = false
			r.buf = append(r.buf, b)
		}
	}
}

func (r *sseEventReader) Close() error {
	return r.inner.Close()
}
