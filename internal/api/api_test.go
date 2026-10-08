package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ricardo-platform/auth/internal/ratelimit"
)

func newTestHandler() http.Handler {
	return New(Deps{
		Log: slog.New(
			slog.NewTextHandler(io.Discard, nil),
		),

		IPLimiter: ratelimit.New(2, time.Minute),

		CORSOrigins: []string{
			"https://app.exemplo.com",
		},
	})
}

func TestNotFoundIsJSON(t *testing.T) {
	rec := httptest.NewRecorder()

	newTestHandler().ServeHTTP(
		rec,
		httptest.NewRequest(
			"GET",
			"/nada",
			nil,
		),
	)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}

	var body map[string]any

	if err := json.Unmarshal(
		rec.Body.Bytes(),
		&body,
	); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}

	if body["success"] != false {
		t.Fatalf(
			"corpo inesperado: %s",
			rec.Body.String(),
		)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()

	newTestHandler().ServeHTTP(
		rec,
		httptest.NewRequest(
			"GET",
			"/api/auth/login",
			nil,
		),
	)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestInvalidJSONAndRateLimit(t *testing.T) {
	h := newTestHandler()

	// As duas primeiras passam pelo limite
	// e caem no decode (400).
	// A terceira é bloqueada (429).

	want := []int{
		http.StatusBadRequest,
		http.StatusBadRequest,
		http.StatusTooManyRequests,
	}

	for i, code := range want {
		req := httptest.NewRequest(
			"POST",
			"/api/auth/login",
			strings.NewReader("{ruim"),
		)

		req.RemoteAddr = "203.0.113.9:1234"

		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		if rec.Code != code {
			t.Fatalf(
				"requisição %d: status %d, esperado %d",
				i+1,
				rec.Code,
				code,
			)
		}
	}
}

func TestCORS(t *testing.T) {
	req := httptest.NewRequest(
		"OPTIONS",
		"/api/auth/login",
		nil,
	)

	req.Header.Set(
		"Origin",
		"https://app.exemplo.com",
	)

	rec := httptest.NewRecorder()

	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf(
			"CORS permitido falhou: status %d",
			rec.Code,
		)
	}

	if rec.Header().Get(
		"Access-Control-Allow-Origin",
	) != "https://app.exemplo.com" {
		t.Fatalf(
			"CORS permitido falhou: %v",
			rec.Header(),
		)
	}

	req = httptest.NewRequest(
		"OPTIONS",
		"/api/auth/login",
		nil,
	)

	req.Header.Set(
		"Origin",
		"https://malicioso.com",
	)

	rec = httptest.NewRecorder()

	newTestHandler().ServeHTTP(rec, req)

	if rec.Header().Get(
		"Access-Control-Allow-Origin",
	) != "" {
		t.Fatal(
			"origem não listada não pode receber Allow-Origin",
		)
	}
}

func TestClientIPTrustProxy(t *testing.T) {
	r := httptest.NewRequest(
		"GET",
		"/",
		nil,
	)

	r.RemoteAddr = "10.0.0.1:5555"

	r.Header.Set(
		"X-Forwarded-For",
		"6.6.6.6, 198.51.100.7",
	)

	if got := clientIP(r, false); got != "10.0.0.1" {
		t.Errorf(
			"sem proxy confiável deveria usar RemoteAddr, veio %s",
			got,
		)
	}

	if got := clientIP(r, true); got != "198.51.100.7" {
		t.Errorf(
			"com proxy confiável deveria usar o último XFF, veio %s",
			got,
		)
	}
}