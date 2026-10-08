package service

import (
	"context"
	"errors"
	"time"

	"github.com/ricardo-platform/auth/internal/apperr"
	"github.com/ricardo-platform/auth/internal/domain"
	"github.com/ricardo-platform/auth/internal/mailer"
	"github.com/ricardo-platform/auth/internal/ratelimit"
	"github.com/ricardo-platform/auth/internal/repository"
	"github.com/ricardo-platform/auth/internal/security"
)

type RegisterService struct {
	users         *repository.UserRepository
	pending       *repository.UserTempRepository
	codes         *security.Codes
	mail          mailer.Mailer
	limiter       *ratelimit.Limiter
	devReturnCode bool
}

func NewRegisterService(
	users *repository.UserRepository,
	pending *repository.UserTempRepository,
	codes *security.Codes,
	mail mailer.Mailer,
	limiter *ratelimit.Limiter,
	devReturnCode bool,
) *RegisterService {

	return &RegisterService{
		users:         users,
		pending:       pending,
		codes:         codes,
		mail:          mail,
		limiter:       limiter,
		devReturnCode: devReturnCode,
	}
}

type RegisterInput struct {
	Nome     string  `json:"nome"`
	Email    string  `json:"email"`
	Telefone *string `json:"telefone"`
	Senha    string  `json:"senha"`
}

type RegisterResult struct {
	Success       bool      `json:"success"`
	Operation     string    `json:"operation"`
	Next          string    `json:"next"`
	Email         string    `json:"email"`
	Message       string    `json:"message"`
	CodigoExpiraEm time.Time `json:"codigo_expira_em"`
	Codigo        string    `json:"codigo,omitempty"`
}

const purposeVerify = string(mailer.PurposeVerification)

func (s *RegisterService) Execute(
	ctx context.Context,
	in RegisterInput,
) (*RegisterResult, error) {

	nome, err := normalizeName(in.Nome)
	if err != nil {
		return nil, err
	}

	email, err := normalizeEmail(in.Email)
	if err != nil {
		return nil, err
	}

	telefone, err := normalizePhone(in.Telefone)
	if err != nil {
		return nil, err
	}

	if err := validatePassword(in.Senha); err != nil {
		return nil, err
	}

	if !s.limiter.Allow("register:" + email) {
		return nil, apperr.RateLimited
	}

	if _, err := s.users.BuscarPorEmail(ctx, email); err == nil {
		return nil, apperr.AccountExists
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, apperr.Internal(err)
	}

	senhaHash, err := security.HashPassword(in.Senha)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	code, err := s.codes.Generate(email, purposeVerify)
	if err != nil {
		return nil, apperr.Internal(err)
	}

	err = s.pending.Salvar(ctx, domain.UserTempInput{
		Nome:           nome,
		Email:          email,
		Telefone:       telefone,
		SenhaHash:      senhaHash,
		CodigoHash:     code.Hash,
		CodigoExpiraEm: code.ExpiresAt,
	})

	if err != nil {
		return nil, apperr.Internal(err)
	}

	if err := s.mail.SendCode(
		ctx,
		email,
		code.Plain,
		mailer.PurposeVerification,
		s.codes.TTL(),
	); err != nil {

		if errors.Is(err, mailer.ErrBusy) {
			return nil, apperr.MailBusy
		}

		return nil, apperr.Internal(err)
	}

	result := &RegisterResult{
		Success:        true,
		Operation:      "account.create",
		Next:           "account.verify",
		Email:          email,
		Message:        "Enviamos um código de verificação para o seu email.",
		CodigoExpiraEm: code.ExpiresAt,
	}

	if s.devReturnCode {
		result.Codigo = code.Plain
	}

	return result, nil
}