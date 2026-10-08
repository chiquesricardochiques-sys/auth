package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ricardo-platform/auth/internal/apperr"
	"github.com/ricardo-platform/auth/internal/domain"
	"github.com/ricardo-platform/auth/internal/repository"
	"github.com/ricardo-platform/auth/internal/security"
)

type VerificationService struct {
	users   *repository.UserRepository
	pending *repository.UserTempRepository
	codes   *security.Codes
}

func NewVerificationService(
	users *repository.UserRepository,
	pending *repository.UserTempRepository,
	codes *security.Codes,
) *VerificationService {

	return &VerificationService{
		users:   users,
		pending: pending,
		codes:   codes,
	}
}

type VerificationInput struct {
	Email  string `json:"email"`
	Codigo string `json:"codigo"`
}

type VerificationResult struct {
	Success   bool         `json:"success"`
	Operation string       `json:"operation"`
	Message   string       `json:"message"`
	Account   *domain.User `json:"account"`
}

func (s *VerificationService) Execute(
	ctx context.Context,
	in VerificationInput,
) (*VerificationResult, error) {

	email, err := normalizeEmail(in.Email)
	if err != nil {
		return nil, err
	}

	codigo := strings.TrimSpace(in.Codigo)

	if codigo == "" {
		return nil, apperr.CodeRequired
	}

	temp, err := s.pending.BuscarPorEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperr.VerificationNotFound
		}

		return nil, apperr.Internal(err)
	}

	if time.Now().After(temp.CodigoExpiraEm) {
		_ = s.pending.Remover(ctx, temp.ID)
		return nil, apperr.CodeExpired
	}

	ok, err := s.pending.ConsumirTentativa(
		ctx,
		temp.ID,
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
		purposeVerify,
		codigo,
		temp.CodigoHash,
	) {
		return nil, apperr.InvalidCode
	}

	user, err := s.users.Criar(ctx, domain.UserInput{
		Nome:            temp.Nome,
		Email:           temp.Email,
		Telefone:        temp.Telefone,
		SenhaHash:       &temp.SenhaHash,
		Status:          domain.StatusAtivo,
		EmailVerificado: true,
	})

	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			_ = s.pending.Remover(ctx, temp.ID)
			return nil, apperr.AccountExists
		}

		return nil, apperr.Internal(err)
	}

	if err := s.pending.Remover(ctx, temp.ID); err != nil {
		return nil, apperr.Internal(err)
	}

	user.SenhaHash = nil

	return &VerificationResult{
		Success:   true,
		Operation: "account.verify",
		Message:   "Conta criada e verificada com sucesso.",
		Account:   user,
	}, nil
}