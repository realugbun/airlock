package middleware

import (
	"net/http"

	"github.com/google/uuid"
	airlocklog "github.com/realugbun/airlock/pkg/log"
)

const (
	// CorrelationHeader is the HTTP header for request correlation.
	CorrelationHeader = "X-Correlation-Id"
	// AgentIDHeader is the HTTP header for agent identification.
	AgentIDHeader = "X-Agent-Id"
)

// Correlation generates or adopts a correlation ID for each request.
func Correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := r.Header.Get(CorrelationHeader)
		if correlationID == "" {
			correlationID = uuid.NewString()
		}

		ctx := airlocklog.WithCorrelationID(r.Context(), correlationID)
		r = r.WithContext(ctx)

		w.Header().Set(CorrelationHeader, correlationID)

		next.ServeHTTP(w, r)
	})
}
