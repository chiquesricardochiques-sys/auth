package service

import (
	"context"
	"errors"
	"strings"

	"github.com/ricardo-platform/auth/internal/apperr"
	"github.com/ricardo-platform/auth/internal/domain"
	"github.com/ricardo-platform/auth/internal/ratelimit"
	"github.com/ricardo-platform/auth/internal/repository"
	"github.com/ricardo-platform/auth/internal/security"
)

type LoginService struct {
	users  *repository.UserRepository
	limiter *ratelimit.Limiter
}

func NewLoginService(
	users *repository.UserRepository,
	limiter *ratelimit.Limiter,
) *LoginService {
	return &LoginService{
		users:   users,
		limiter: limiter,
	}
}

type LoginInput struct {
	Email string `json:"email"`
	Senha string `json:"senha"`
}

type LoginResult struct {
	Success   bool         `json:"success"`
	Operation string       `json:"operation"`
	User      *domain.User `json:"user"`
}

func (s *LoginService) Execute(
	ctx context.Context,
	in LoginInput,
	ci ClientInfo,
) (*LoginResult, error) {

	email := strings.ToLower(strings.TrimSpace(in.Email))

	if email == "" || in.Senha == "" {
		return nil, apperr.InvalidCredentials
	}

	key := ci.IP + "|" + email

	if !s.limiter.Allow(key) {
		return nil, apperr.RateLimited
	}

	user, err := s.users.BuscarPorEmail(ctx, email)

	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			security.BurnCPU(in.Senha)
			return nil, apperr.InvalidCredentials
		}

		return nil, apperr.Internal(err)
	}

	if user.SenhaHash == nil {
		security.BurnCPU(in.Senha)
		return nil, apperr.InvalidCredentials
	}

	if !security.CheckPassword(in.Senha, *user.SenhaHash) {
		return nil, apperr.InvalidCredentials
	}

	if user.Status != domain.StatusAtivo {
		return nil, apperr.AccountInactive
	}

	s.limiter.Reset(key)

	user.SenhaHash = nil

	return &LoginResult{
		Success:   true,
		Operation: "authentication.login",
		User:      user,
	}, nil
}