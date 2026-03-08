package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/stretchr/testify/assert"
)

func TestCorrelation_GeneratesID(t *testing.T) {
	var capturedID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = airlocklog.CorrelationIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := Correlation(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.NotEmpty(t, capturedID)
	assert.Equal(t, capturedID, rec.Header().Get(CorrelationHeader))
}

func TestCorrelation_AdoptsExisting(t *testing.T) {
	existingID := "my-custom-correlation-id"
	var capturedID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = airlocklog.CorrelationIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := Correlation(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(CorrelationHeader, existingID)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, existingID, capturedID)
	assert.Equal(t, existingID, rec.Header().Get(CorrelationHeader))
}
