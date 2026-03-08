package proxy

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdleTimeout_NormalReads(t *testing.T) {
	data := "hello world"
	canceled := make(chan struct{})
	cancel := func() { close(canceled) }

	r := newIdleTimeoutReader(
		io.NopCloser(strings.NewReader(data)),
		100*time.Millisecond,
		cancel,
	)

	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, data, string(out))

	// Cancel should not have fired.
	select {
	case <-canceled:
		t.Fatal("cancel should not have been called during active reads")
	default:
	}

	_ = r.Close()
}

func TestIdleTimeout_CancelsAfterIdle(t *testing.T) {
	canceled := make(chan struct{})
	cancel := func() {
		select {
		case <-canceled:
		default:
			close(canceled)
		}
	}

	// Use a pipe so we can control when data arrives.
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()

	r := newIdleTimeoutReader(pr, 50*time.Millisecond, cancel)
	defer func() { _ = r.Close() }()

	// Write data so first read succeeds.
	go func() { _, _ = pw.Write([]byte("hello")) }()

	buf := make([]byte, 64)
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))

	// Don't write anything else — idle timeout should fire.
	select {
	case <-canceled:
		// Good — cancel was called.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected cancel to be called after idle period")
	}
}

func TestIdleTimeout_ActiveReadsResetTimer(t *testing.T) {
	canceled := make(chan struct{})
	cancel := func() {
		select {
		case <-canceled:
		default:
			close(canceled)
		}
	}

	// Use tinyReader that returns data in small chunks with no delay.
	// The idle timeout is long enough that fast reads should prevent it.
	r := newIdleTimeoutReader(
		io.NopCloser(&tinyReader{data: []byte(strings.Repeat("x", 200)), chunkSize: 10}),
		100*time.Millisecond,
		cancel,
	)

	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Len(t, out, 200)

	// Cancel should not have fired.
	select {
	case <-canceled:
		t.Fatal("cancel should not fire during active reads")
	default:
	}

	_ = r.Close()
}

func TestIdleTimeout_CloseStopsTimer(t *testing.T) {
	canceled := make(chan struct{})
	cancel := func() {
		select {
		case <-canceled:
		default:
			close(canceled)
		}
	}

	r := newIdleTimeoutReader(
		io.NopCloser(strings.NewReader("")),
		50*time.Millisecond,
		cancel,
	)

	// Close immediately — timer should be stopped.
	_ = r.Close()

	// Wait longer than the timeout.
	time.Sleep(100 * time.Millisecond)

	select {
	case <-canceled:
		t.Fatal("cancel should not fire after Close")
	default:
	}
}
