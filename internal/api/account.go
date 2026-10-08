package api

import (
	"net/http"
	"strconv"

	"github.com/ricardo-platform/auth/internal/apperr"
)

// ACCOUNT ID

func accountIDFromQuery(r *http.Request) (uint64, error) {
	value := r.URL.Query().Get("id")
	if value == "" {
		return 0, apperr.AccountNotFound
	}

	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || id == 0 {
		return 0, apperr.AccountNotFound
	}

	return id, nil
}

// GET /api/auth/account?id=ID

func (a *API) account(w http.ResponseWriter, r *http.Request) error {
	id, err := accountIDFromQuery(r)
	if err != nil {
		return err
	}

	user, err := a.Accounts.Consult(r.Context(), id)
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"operation": "account.consult",
		"account":   user,
	})

	return nil
}