package proxy

import (
	"context"
	"io"
	"time"
)

// idleCancelKey is the context key for the cancel function used by the idle timeout reader.
type idleCancelKey struct{}

func withIdleCancel(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	return context.WithValue(ctx, idleCancelKey{}, cancel), cancel
}

func idleCancelFromContext(ctx context.Context) context.CancelFunc {
	if fn, ok := ctx.Value(idleCancelKey{}).(context.CancelFunc); ok {
		return fn
	}
	return nil
}

// idleTimeoutReader wraps an io.ReadCloser and cancels the associated context
// if no bytes are received within the idle timeout period. This catches upstream
// stalls during streaming responses without killing healthy long-running streams
// that are actively producing data.
//
// The timer starts on creation (catching stalls between response headers and
// the first body byte) and resets on every successful Read.
type idleTimeoutReader struct {
	inner   io.ReadCloser
	timer   *time.Timer
	timeout time.Duration
}

func newIdleTimeoutReader(r io.ReadCloser, timeout time.Duration, cancel context.CancelFunc) *idleTimeoutReader {
	return &idleTimeoutReader{
		inner:   r,
		timeout: timeout,
		timer:   time.AfterFunc(timeout, cancel),
	}
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if n > 0 {
		r.timer.Reset(r.timeout)
	}
	return n, err
}

func (r *idleTimeoutReader) Close() error {
	r.timer.Stop()
	return r.inner.Close()
}
