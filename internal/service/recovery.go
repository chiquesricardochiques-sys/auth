package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ricardo-platform/auth/internal/apperr"
	"github.com/ricardo-platform/auth/internal/domain"
	"github.com/ricardo-platform/auth/internal/mailer"
	"github.com/ricardo-platform/auth/internal/ratelimit"
	"github.com/ricardo-platform/auth/internal/repository"
	"github.com/ricardo-platform/auth/internal/security"
)

type RecoveryService struct {
	users         *repository.UserRepository
	recovery      *repository.PasswordRecoveryRepository
	codes         *security.Codes
	mail          mailer.Mailer
	limiter       *ratelimit.Limiter
	devReturnCode bool
}

func NewRecoveryService(
	users *repository.UserRepository,
	recovery *repository.PasswordRecoveryRepository,
	codes *security.Codes,
	mail mailer.Mailer,
	limiter *ratelimit.Limiter,
	devReturnCode bool,
) *RecoveryService {

	return &RecoveryService{
		users:         users,
		recovery:      recovery,
		codes:         codes,
		mail:          mail,
		limiter:       limiter,
		devReturnCode: devReturnCode,
	}
}

type RecoveryRequestInput struct {
	Email         string `json:"email"`
	Senha         string `json:"senha"`
	ConfirmarSenha string `json:"confirmar_senha"`
}

type RecoveryRequestResult struct {
	Success        bool      `json:"success"`
	Operation      string    `json:"operation"`
	Message        string    `json:"message"`
	Email          string    `json:"email"`
	Next           string    `json:"next"`
	CodigoExpiraEm time.Time `json:"codigo_expira_em"`
	Codigo         string    `json:"codigo,omitempty"`
}

type RecoveryVerifyInput struct {
	Email  string `json:"email"`
	Codigo string `json:"codigo"`
}

type RecoveryVerifyResult struct {
	Success   bool   `json:"success"`
	Operation string `json:"operation"`
	Message   string `json:"message"`
}

const purposeRecovery = string(mailer.PurposeRecovery)

func (s *RecoveryService) Request(
	ctx context.Context,
	in RecoveryRequestInput,
) (*RecoveryRequestResult, error) {

	email, err := normalizeEmail(in.Email)
	if err != nil {
		return nil, err
	}

	if err := validatePassword(in.Senha); err != nil {
		return nil, err
	}

	if in.Senha != in.ConfirmarSenha {
		return nil, apperr.PasswordMismatch
	}

	if !s.limiter.Allow("recovery:" + email) {
		return nil, apperr.RateLimited
	}

	senhaHash, err := security.HashPassword(in.Senha)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	code, err := s.codes.Generate(email, purposeRecovery)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	result := &RecoveryRequestResult{
		Success:        true,
		Operation:      "recovery.request",
		Message:        "Se existir uma conta com este email, enviaremos um código de verificação.",
		Email:          email,
		Next:           "recovery.verify",
		CodigoExpiraEm: code.ExpiresAt,
	}

	user, err := s.users.BuscarPorEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return result, nil
		}

		return nil, apperr.Internal(err)
	}

	if user.Status != domain.StatusAtivo {
		return result, nil
	}

	if err := s.recovery.Salvar(ctx, domain.PasswordRecoveryInput{
		Email:          email,
		SenhaHash:      senhaHash,
		CodigoHash:     code.Hash,
		CodigoExpiraEm: code.ExpiresAt,
	}); err != nil {
		return nil, apperr.Internal(err)
	}

	if err := s.mail.SendCode(
		ctx,
		email,
		code.Plain,
		mailer.PurposeRecovery,
		s.codes.TTL(),
	); err != nil {

		if errors.Is(err, mailer.ErrBusy) {
			return nil, apperr.MailBusy
		}

		return nil, apperr.Internal(err)
	}

	if s.devReturnCode {
		result.Codigo = code.Plain
	}

	return result, nil
}

func (s *RecoveryService) Verify(
	ctx context.Context,
	in RecoveryVerifyInput,
) (*RecoveryVerifyResult, error) {

	email, err := normalizeEmail(in.Email)
	if err != nil {
		return nil, err
	}

	codigo := strings.TrimSpace(in.Codigo)

	if codigo == "" {
		return nil, apperr.CodeRequired
	}

	recovery, err := s.recovery.BuscarPorEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperr.InvalidCode
		}

		return nil, apperr.Internal(err)
	}

	if time.Now().After(recovery.CodigoExpiraEm) {
		_ = s.recovery.Remover(ctx, recovery.ID)
		return nil, apperr.InvalidCode
	}

	ok, err := s.recovery.ConsumirTentativa(
		ctx,
		recovery.ID,
		MaxCodeAttempts,
	)

	if err != nil {
		return nil, apperr.Internal(err)
	}

	if !ok {
		return nil, apperr.TooManyAttempts
	}

	if !s.codes.Check(
		email,
		purposeRecovery,
		codigo,
		recovery.CodigoHash,
	) {
		return nil, apperr.InvalidCode
	}

	user, err := s.users.BuscarPorEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			_ = s.recovery.Remover(ctx, recovery.ID)
			return nil, apperr.InvalidCode
		}

		return nil, apperr.Internal(err)
	}

	if err := s.users.AtualizarSenha(
		ctx,
		user.ID,
		recovery.SenhaHash,
	); err != nil {
		return nil, apperr.Internal(err)
	}

	if err := s.recovery.Remover(ctx, recovery.ID); err != nil {
		return nil, apperr.Internal(err)
	}

	return &RecoveryVerifyResult{
		Success:   true,
		Operation: "recovery.reset",
		Message:   "Senha alterada com sucesso.",
	}, nil
}