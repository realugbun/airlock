package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	airlocklog "github.com/realugbun/airlock/pkg/log"
)

// RequestLog holds per-request metadata set by downstream handlers.
type RequestLog struct {
	Route      string
	TargetPath string
	Message    string
}

type requestLogKey struct{}

func withRequestLog(ctx context.Context, rl *RequestLog) context.Context {
	return context.WithValue(ctx, requestLogKey{}, rl)
}

// RequestLogFromContext retrieves the RequestLog pointer from the context.
func RequestLogFromContext(ctx context.Context) *RequestLog {
	if rl, ok := ctx.Value(requestLogKey{}).(*RequestLog); ok {
		return rl
	}
	return nil
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying ResponseWriter if it implements
// http.Flusher. This is required for streaming responses (SSE) —
// httputil.ReverseProxy checks for http.Flusher to decide whether to
// flush each chunk immediately or buffer the entire response.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// RequestLogger logs each request after the handler chain completes.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			rl := &RequestLog{}
			ctx := withRequestLog(r.Context(), rl)
			r = r.WithContext(ctx)

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			correlationID := airlocklog.CorrelationIDFromContext(r.Context())

			attrs := []any{
				"correlation_id", correlationID,
				"method", r.Method,
				"path", r.URL.Path,
				"duration_ms", duration.Milliseconds(),
			}

			msg := "handled request"

			if rl.Route != "" {
				attrs = append(attrs, "route", rl.Route)
			}
			if rl.TargetPath != "" {
				attrs = append(attrs, "target_path", rl.TargetPath)
			}
			if rl.Message != "" {
				msg = rl.Message
			}

			attrs = append(attrs, "upstream_status", wrapped.statusCode)

			level := slog.LevelInfo
			if wrapped.statusCode >= 500 {
				level = slog.LevelError
			} else if wrapped.statusCode >= 400 {
				level = slog.LevelWarn
			}

			logger.Log(r.Context(), level, msg, attrs...)
		})
	}
}
