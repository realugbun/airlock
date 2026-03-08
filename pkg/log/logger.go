package log

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"time"
)

type ctxKey string

const correlationKey ctxKey = "correlation_id"

const timestampFormat = "2006-01-02T15:04:05.000Z"

// NewLogger creates an slog.Logger with JSON output and the required base fields.
func NewLogger(w io.Writer, service, agentID string) *slog.Logger {
	opts := &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				a.Key = "timestamp"
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.UTC().Format(timestampFormat))
				}
			case slog.MessageKey:
				a.Key = "message"
			case slog.LevelKey:
				a.Key = "level"
				a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
			}
			return a
		},
	}

	handler := slog.NewJSONHandler(w, opts)

	attrs := []slog.Attr{
		slog.String("service", service),
	}
	if agentID != "" {
		attrs = append(attrs, slog.String("agent_id", agentID))
	}

	return slog.New(handler.WithAttrs(attrs))
}

// WithCorrelationID stores a correlation ID in the context.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey, id)
}

// CorrelationIDFromContext retrieves the correlation ID from the context.
func CorrelationIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(correlationKey).(string); ok {
		return id
	}
	return ""
}
