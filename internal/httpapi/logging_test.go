package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestLogDecision(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		status   int
		duration time.Duration
		level    slog.Level
		message  string
		emit     bool
	}{
		{name: "successful read", method: http.MethodGet, status: http.StatusOK},
		{name: "successful head", method: http.MethodHead, status: http.StatusNoContent},
		{name: "preflight", method: http.MethodOptions, status: http.StatusNoContent},
		{name: "slow read", method: http.MethodGet, status: http.StatusOK, duration: slowReadRequestThreshold, level: slog.LevelWarn, message: "slow HTTP read request completed", emit: true},
		{name: "mutation", method: http.MethodDelete, status: http.StatusNoContent, level: slog.LevelInfo, message: "HTTP request completed", emit: true},
		{name: "client error", method: http.MethodGet, status: http.StatusUnauthorized, level: slog.LevelWarn, message: "HTTP request rejected", emit: true},
		{name: "server error", method: http.MethodPost, status: http.StatusInternalServerError, level: slog.LevelError, message: "HTTP request failed", emit: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			level, message, emit := requestLogDecision(test.method, test.status, test.duration)
			if level != test.level || message != test.message || emit != test.emit {
				t.Fatalf("decision = (%s, %q, %t), want (%s, %q, %t)", level, message, emit, test.level, test.message, test.emit)
			}
		})
	}
}

func TestRequestLogMiddlewareSuppressesSuccessfulReads(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := requestLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), logger)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/model-providers", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if output.Len() != 0 {
		t.Fatalf("successful read produced an access log: %s", output.String())
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("request ID header was not preserved")
	}
}

func TestRequestLogMiddlewareKeepsMutationAndErrorContext(t *testing.T) {
	for _, test := range []struct {
		name        string
		method      string
		status      int
		wantLevel   string
		wantMessage string
	}{
		{name: "mutation", method: http.MethodPost, status: http.StatusCreated, wantLevel: `"level":"INFO"`, wantMessage: "HTTP request completed"},
		{name: "error", method: http.MethodGet, status: http.StatusBadRequest, wantLevel: `"level":"WARN"`, wantMessage: "HTTP request rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := requestLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
			}), logger)
			request := httptest.NewRequest(test.method, "/api/v1/test", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			logged := output.String()
			for _, expected := range []string{test.wantLevel, test.wantMessage, `"request_id":`, `"status":`, `"duration_ms":`, `"response_bytes":`} {
				if !strings.Contains(logged, expected) {
					t.Fatalf("log is missing %q: %s", expected, logged)
				}
			}
		})
	}
}
