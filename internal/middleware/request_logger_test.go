package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestLogger_LogsRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := airlocklog.NewLogger(&buf, "test-svc", "")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rl := RequestLogFromContext(r.Context()); rl != nil {
			rl.Route = "/openai"
			rl.TargetPath = "/v1/chat/completions"
			rl.Message = "proxied request"
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestLogger(logger)(inner)
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	ctx := airlocklog.WithCorrelationID(req.Context(), "test-corr-id")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	assert.Equal(t, "proxied request", entry["message"])
	assert.Equal(t, "/openai", entry["route"])
	assert.Equal(t, "/v1/chat/completions", entry["target_path"])
	assert.Equal(t, "/openai/v1/chat/completions", entry["path"])
	assert.Equal(t, "test-corr-id", entry["correlation_id"])
}

func TestRequestLogger_Warn4xx(t *testing.T) {
	var buf bytes.Buffer
	logger := airlocklog.NewLogger(&buf, "test-svc", "")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	})

	handler := RequestLogger(logger)(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	assert.Equal(t, "warn", entry["level"])
}
