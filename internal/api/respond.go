package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/ricardo-platform/auth/internal/apperr"
)

const maxBodyBytes = 64 << 10 // 64 KB

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return apperr.InvalidJSON
	}

	if err := json.Unmarshal(body, dst); err != nil {
		return apperr.InvalidJSON
	}

	return nil
}

func (a *API) fail(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	e := apperr.From(err)

	if e.Status >= 500 {
		a.log.Error(
			"erro interno",
			"method", r.Method,
			"path", r.URL.Path,
			"code", e.Code,
			"err", e.Err,
		)
	}

	if e.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", strconv.Itoa(60))
	}

	writeJSON(w, e.Status, map[string]any{
		"success": false,
		"code":    e.Code,
		"message": e.Message,
	})
}
