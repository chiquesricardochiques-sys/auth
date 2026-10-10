package api

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ricardo-platform/auth/internal/ratelimit"
)

// ---------------------------------------------------------------------------
// IP do cliente
// ---------------------------------------------------------------------------

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")

			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// ---------------------------------------------------------------------------
// Recuperação contra panic
// ---------------------------------------------------------------------------

func recoverer(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			defer func() {
				if rec := recover(); rec != nil {
					log.Error(
						"panic",
						"path", r.URL.Path,
						"recover", rec,
					)

					writeJSON(w, http.StatusInternalServerError, map[string]any{
						"success": false,
						"code":    "INTERNAL_ERROR",
						"message": "Erro interno. Tente novamente mais tarde.",
					})
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Log HTTP
// ---------------------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func accessLog(log *slog.Logger, trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			start := time.Now()

			rec := &statusRecorder{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			next.ServeHTTP(rec, r)

			log.Info(
				"http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"ms", time.Since(start).Milliseconds(),
				"ip", clientIP(r, trustProxy),
			)
		})
	}
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		h := w.Header()

		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")

		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CORS Totalmente Liberado para Múltiplos Serviços
// ---------------------------------------------------------------------------

func cors(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			origin := r.Header.Get("Origin")

			// Se a requisição vier com uma origem, reflete ela dinamicamente.
			// Se não vier (ex: requisições de servidores, curl, Postman), usa o curinga "*".
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set(
				"Access-Control-Allow-Methods",
				"GET, POST, PUT, DELETE, OPTIONS",
			)
			w.Header().Set(
				"Access-Control-Allow-Headers",
				"Content-Type, Authorization, X-Service-Key",
			)
			w.Header().Set("Access-Control-Max-Age", "600")
			w.Header().Add("Vary", "Origin")

			// Responde imediatamente às requisições pré-voo (OPTIONS) dos navegadores
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
// ---------------------------------------------------------------------------
// Rate limit por IP
// ---------------------------------------------------------------------------

func (a *API) limitByIP(
	l *ratelimit.Limiter,
	next http.HandlerFunc,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if !l.Allow(clientIP(r, a.trustProxy)) {
			a.fail(w, r, errRateLimited)
			return
		}

		next(w, r)
	}
}
