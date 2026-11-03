package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewServerLimits(t *testing.T) {
	s := newServer(":0", http.NotFoundHandler())
	assert.Positive(t, s.ReadHeaderTimeout)
	assert.Positive(t, s.IdleTimeout)
	assert.Positive(t, s.MaxHeaderBytes)
	// Long-lived SSE streams must not be cut off by server-wide timeouts.
	assert.Zero(t, s.ReadTimeout)
	assert.Zero(t, s.WriteTimeout)
}
