package repository

import (
	"context"
	"database/sql"

	"github.com/ricardo-platform/auth/internal/domain"
)

type UserRepository struct {
	DB *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		DB: db,
	}
}

const userColumns = `
	id,
	nome,
	email,
	telefone,
	senha_hash,
	status,
	email_verificado
`

func scanUser(row *sql.Row) (*domain.User, error) {
	var user domain.User

	err := row.Scan(
		&user.ID,
		&user.Nome,
		&user.Email,
		&user.Telefone,
		&user.SenhaHash,
		&user.Status,
		&user.EmailVerificado,
	)

	if err != nil {
		return nil, mapError(err)
	}

	return &user, nil
}

func (r *UserRepository) Criar(
	ctx context.Context,
	input domain.UserInput,
) (*domain.User, error) {

	result, err := r.DB.ExecContext(
		ctx,
		`
		INSERT INTO users (
			nome,
			email,
			telefone,
			senha_hash,
			status,
			email_verificado
		)
		VALUES (?, ?, ?, ?, ?, ?)
		`,
		input.Nome,
		input.Email,
		input.Telefone,
		input.SenhaHash,
		input.Status,
		input.EmailVerificado,
	)

	if err != nil {
		return nil, mapError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return r.BuscarPorID(ctx, uint64(id))
}

func (r *UserRepository) BuscarPorID(
	ctx context.Context,
	id uint64,
) (*domain.User, error) {

	return scanUser(
		r.DB.QueryRowContext(
			ctx,
			`SELECT `+userColumns+` FROM users WHERE id = ? LIMIT 1`,
			id,
		),
	)
}

func (r *UserRepository) BuscarPorEmail(
	ctx context.Context,
	email string,
) (*domain.User, error) {

	return scanUser(
		r.DB.QueryRowContext(
			ctx,
			`SELECT `+userColumns+` FROM users WHERE email = ? LIMIT 1`,
			email,
		),
	)
}

func (r *UserRepository) Atualizar(
	ctx context.Context,
	id uint64,
	nome string,
	telefone *string,
) (*domain.User, error) {

	_, err := r.DB.ExecContext(
		ctx,
		`
		UPDATE users
		SET
			nome = ?,
			telefone = ?
		WHERE id = ?
		`,
		nome,
		telefone,
		id,
	)

	if err != nil {
		return nil, mapError(err)
	}

	return r.BuscarPorID(ctx, id)
}

func (r *UserRepository) AtualizarSenha(
	ctx context.Context,
	id uint64,
	senhaHash string,
) error {

	_, err := r.DB.ExecContext(
		ctx,
		`
		UPDATE users
		SET senha_hash = ?
		WHERE id = ?
		`,
		senhaHash,
		id,
	)

	return mapError(err)
}

func (r *UserRepository) Remover(
	ctx context.Context,
	id uint64,
) error {

	_, err := r.DB.ExecContext(
		ctx,
		`DELETE FROM users WHERE id = ?`,
		id,
	)

	return mapError(err)
}