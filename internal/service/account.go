package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/ricardo-platform/auth/internal/apperr"
	"github.com/ricardo-platform/auth/internal/domain"
	"github.com/ricardo-platform/auth/internal/ratelimit"
	"github.com/ricardo-platform/auth/internal/repository"
	"github.com/ricardo-platform/auth/internal/security"
)

type AccountService struct {
	users  *repository.UserRepository
	limiter *ratelimit.Limiter
}

func NewAccountService(
	users *repository.UserRepository,
	limiter *ratelimit.Limiter,
) *AccountService {
	return &AccountService{
		users:   users,
		limiter: limiter,
	}
}

func (s *AccountService) Consult(
	ctx context.Context,
	id uint64,
) (*domain.User, error) {

	user, err := s.users.BuscarPorID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperr.AccountNotFound
		}

		return nil, apperr.Internal(err)
	}

	user.SenhaHash = nil

	return user, nil
}

func (s *AccountService) UpdateProfile(
	ctx context.Context,
	id uint64,
	nome string,
	telefone *string,
) (*domain.User, error) {

	nome, err := normalizeName(nome)
	if err != nil {
		return nil, err
	}

	telefone, err = normalizePhone(telefone)
	if err != nil {
		return nil, err
	}

	user, err := s.users.Atualizar(ctx, id, nome, telefone)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperr.AccountNotFound
		}

		return nil, apperr.Internal(err)
	}

	user.SenhaHash = nil

	return user, nil
}

func (s *AccountService) confirmPassword(
	ctx context.Context,
	id uint64,
	senha string,
) error {

	if senha == "" {
		return apperr.PasswordRequired
	}

	if !s.limiter.Allow(fmt.Sprintf("pwd:%d", id)) {
		return apperr.RateLimited
	}

	user, err := s.users.BuscarPorID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperr.AccountNotFound
		}

		return apperr.Internal(err)
	}

	if user.SenhaHash == nil ||
		!security.CheckPassword(senha, *user.SenhaHash) {

		return apperr.WrongPassword
	}

	return nil
}

func (s *AccountService) ChangePassword(
	ctx context.Context,
	id uint64,
	atual string,
	nova string,
) error {

	if err := s.confirmPassword(ctx, id, atual); err != nil {
		return err
	}

	if err := validatePassword(nova); err != nil {
		return err
	}

	hash, err := security.HashPassword(nova)
	if err != nil {
		return apperr.Internal(err)
	}

	if err := s.users.AtualizarSenha(ctx, id, hash); err != nil {
		return apperr.Internal(err)
	}

	return nil
}

func (s *AccountService) Delete(
	ctx context.Context,
	id uint64,
	senha string,
) error {

	if err := s.confirmPassword(ctx, id, senha); err != nil {
		return err
	}

	if err := s.users.Remover(ctx, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperr.AccountNotFound
		}

		return apperr.Internal(err)
	}

	return nil
}