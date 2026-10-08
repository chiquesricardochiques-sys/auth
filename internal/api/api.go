package api

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ricardo-platform/auth/internal/apperr"
	"github.com/ricardo-platform/auth/internal/ratelimit"
	"github.com/ricardo-platform/auth/internal/service"
)

var errRateLimited = apperr.RateLimited

type Deps struct {
	Log *slog.Logger
	DB  *sql.DB

	Register *service.RegisterService
	Verify   *service.VerificationService
	Login    *service.LoginService
	Recovery *service.RecoveryService
	Accounts *service.AccountService

	IPLimiter *ratelimit.Limiter

	CORSOrigins []string
	TrustProxy  bool
}

type API struct {
	Deps
	log        *slog.Logger
	trustProxy bool
}

func New(d Deps) http.Handler {
	a := &API{
		Deps:       d,
		log:        d.Log,
		trustProxy: d.TrustProxy,
	}

	mux := http.NewServeMux()

	routes := map[string][]string{}

	route := func(method, path string, h http.HandlerFunc) {
		mux.HandleFunc(method+" "+path, h)
		routes[path] = append(routes[path], method)
	}

	// -----------------------------------------------------------------------
	// Públicas
	// -----------------------------------------------------------------------

	route(
		"GET",
		"/api/auth/health",
		a.health,
	)

	route(
		"POST",
		"/api/auth/register",
		a.limitByIP(a.IPLimiter, a.handle(a.register)),
	)

	route(
		"POST",
		"/api/auth/verify",
		a.limitByIP(a.IPLimiter, a.handle(a.verify)),
	)

	route(
		"POST",
		"/api/auth/login",
		a.limitByIP(a.IPLimiter, a.handle(a.login)),
	)

	route(
		"POST",
		"/api/auth/recovery",
		a.limitByIP(a.IPLimiter, a.handle(a.recoveryRequest)),
	)

	route(
		"POST",
		"/api/auth/recovery/verify",
		a.limitByIP(a.IPLimiter, a.handle(a.recoveryVerify)),
	)

	// -----------------------------------------------------------------------
	// Conta
	// -----------------------------------------------------------------------

	route(
		"GET",
		"/api/auth/account",
		a.handle(a.getAccount),
	)

	route(
		"PUT",
		"/api/auth/account",
		a.handle(a.updateAccount),
	)

	route(
		"PUT",
		"/api/auth/account/password",
		a.limitByIP(a.IPLimiter, a.handle(a.changePassword)),
	)

	route(
		"DELETE",
		"/api/auth/account",
		a.limitByIP(a.IPLimiter, a.handle(a.deleteAccount)),
	)

	// -----------------------------------------------------------------------
	// Fallback
	// -----------------------------------------------------------------------

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if methods, ok := routes[r.URL.Path]; ok {
			w.Header().Set("Allow", strings.Join(methods, ", "))
			a.fail(w, r, apperr.MethodNotAllowed)
			return
		}

		a.fail(w, r, apperr.NotFound)
	})

	var h http.Handler = mux

	h = cors(d.CORSOrigins)(h)
	h = securityHeaders(h)
	h = accessLog(d.Log, d.TrustProxy)(h)
	h = recoverer(d.Log)(h)

	return h
}

// ---------------------------------------------------------------------------
// Adaptadores
// ---------------------------------------------------------------------------

func (a *API) handle(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			a.fail(w, r, err)
		}
	}
}

func (a *API) clientInfo(r *http.Request) service.ClientInfo {
	return service.ClientInfo{
		IP:        clientIP(r, a.trustProxy),
		UserAgent: r.UserAgent(),
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := a.DB.PingContext(ctx); err != nil {
		a.log.Error("health: banco indisponível", "err", err)

		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false,
			"service": "auth-api",
			"status":  "degraded",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"service": "auth-api",
		"status":  "online",
	})
}

// ---------------------------------------------------------------------------
// Registro
// ---------------------------------------------------------------------------

func (a *API) register(w http.ResponseWriter, r *http.Request) error {
	var in service.RegisterInput

	if err := decode(w, r, &in); err != nil {
		return err
	}

	res, err := a.Register.Execute(r.Context(), in)
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, res)
	return nil
}

// ---------------------------------------------------------------------------
// Verificação de email
// ---------------------------------------------------------------------------

func (a *API) verify(w http.ResponseWriter, r *http.Request) error {
	var in service.VerificationInput

	if err := decode(w, r, &in); err != nil {
		return err
	}

	res, err := a.Verify.Execute(r.Context(), in)
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, res)
	return nil
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func (a *API) login(w http.ResponseWriter, r *http.Request) error {
	var in service.LoginInput

	if err := decode(w, r, &in); err != nil {
		return err
	}

	res, err := a.Login.Execute(
		r.Context(),
		in,
		a.clientInfo(r),
	)
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, res)
	return nil
}

// ---------------------------------------------------------------------------
// Recuperação de senha
// ---------------------------------------------------------------------------

func (a *API) recoveryRequest(w http.ResponseWriter, r *http.Request) error {
	var in service.RecoveryRequestInput

	if err := decode(w, r, &in); err != nil {
		return err
	}

	res, err := a.Recovery.Request(r.Context(), in)
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, res)
	return nil
}

func (a *API) recoveryVerify(w http.ResponseWriter, r *http.Request) error {
	var in service.RecoveryVerifyInput

	if err := decode(w, r, &in); err != nil {
		return err
	}

	res, err := a.Recovery.Verify(r.Context(), in)
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, res)
	return nil
}

// ---------------------------------------------------------------------------
// Conta
// ---------------------------------------------------------------------------

func (a *API) getAccount(w http.ResponseWriter, r *http.Request) error {
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

func (a *API) updateAccount(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		ID       uint64  `json:"id"`
		Nome     string  `json:"nome"`
		Telefone *string `json:"telefone"`
	}

	if err := decode(w, r, &in); err != nil {
		return err
	}

	if in.ID == 0 {
		return apperr.AccountNotFound
	}

	user, err := a.Accounts.UpdateProfile(
		r.Context(),
		in.ID,
		in.Nome,
		in.Telefone,
	)
	if err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"operation": "account.edit",
		"account":   user,
	})

	return nil
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		ID         uint64 `json:"id"`
		SenhaAtual string `json:"senha_atual"`
		NovaSenha  string `json:"nova_senha"`
	}

	if err := decode(w, r, &in); err != nil {
		return err
	}

	if in.ID == 0 {
		return apperr.AccountNotFound
	}

	if err := a.Accounts.ChangePassword(
		r.Context(),
		in.ID,
		in.SenhaAtual,
		in.NovaSenha,
	); err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"operation": "account.change_password",
		"message":   "Senha alterada com sucesso.",
	})

	return nil
}

func (a *API) deleteAccount(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		ID    uint64 `json:"id"`
		Senha string `json:"senha"`
	}

	if err := decode(w, r, &in); err != nil {
		return err
	}

	if in.ID == 0 {
		return apperr.AccountNotFound
	}

	if err := a.Accounts.Delete(
		r.Context(),
		in.ID,
		in.Senha,
	); err != nil {
		return err
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"operation": "account.delete",
		"message":   "Conta excluída.",
	})

	return nil
}