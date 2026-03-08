package log

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_RequiredFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "github.com/realugbun/airlock", "test-agent")

	logger.Info("proxied request",
		"correlation_id", "87bab423-2bc8-4096-b4d9-0c408657c71c",
		"route", "/openai",
	)

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	assert.Equal(t, "github.com/realugbun/airlock", entry["service"])
	assert.Equal(t, "test-agent", entry["agent_id"])
	assert.Equal(t, "info", entry["level"])
	assert.Equal(t, "proxied request", entry["message"])
	assert.Contains(t, entry, "timestamp")
	assert.Contains(t, entry, "correlation_id")
}

func TestLogger_NoAgentID(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "github.com/realugbun/airlock", "")

	logger.Info("test message")

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	assert.Equal(t, "github.com/realugbun/airlock", entry["service"])
	assert.NotContains(t, entry, "agent_id")
}

func TestLogger_LevelLowercase(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "svc", "")

	logger.Warn("warning message")

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	assert.Equal(t, "warn", entry["level"])
}

func TestLogger_TimestampFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "svc", "")

	logger.Info("test")

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	ts, ok := entry["timestamp"].(string)
	require.True(t, ok)
	assert.Regexp(t, `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`, ts)
}

func TestCorrelationIDContext(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", CorrelationIDFromContext(ctx))

	ctx = WithCorrelationID(ctx, "test-id-123")
	assert.Equal(t, "test-id-123", CorrelationIDFromContext(ctx))
}
