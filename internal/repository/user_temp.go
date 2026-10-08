package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ricardo-platform/auth/internal/domain"
)

type UserTempRepository struct {
	DB *sql.DB
}

func NewUserTempRepository(db *sql.DB) *UserTempRepository {
	return &UserTempRepository{
		DB: db,
	}
}

func (r *UserTempRepository) BuscarPorEmail(
	ctx context.Context,
	email string,
) (*domain.UserTemp, error) {

	var temp domain.UserTemp

	err := r.DB.QueryRowContext(
		ctx,
		`
		SELECT
			id,
			nome,
			email,
			telefone,
			senha_hash,
			codigo_hash,
			codigo_expira_em,
			tentativas
		FROM users_temp
		WHERE email = ?
		ORDER BY id DESC
		LIMIT 1
		`,
		email,
	).Scan(
		&temp.ID,
		&temp.Nome,
		&temp.Email,
		&temp.Telefone,
		&temp.SenhaHash,
		&temp.CodigoHash,
		&temp.CodigoExpiraEm,
		&temp.Tentativas,
	)

	if err != nil {
		return nil, mapError(err)
	}

	return &temp, nil
}

func (r *UserTempRepository) Salvar(
	ctx context.Context,
	input domain.UserTempInput,
) error {

	for tentativa := 0; tentativa < 2; tentativa++ {
		result, err := r.DB.ExecContext(
			ctx,
			`
			UPDATE users_temp
			SET
				nome = ?,
				telefone = ?,
				senha_hash = ?,
				codigo_hash = ?,
				codigo_expira_em = ?,
				tentativas = 0
			WHERE email = ?
			`,
			input.Nome,
			input.Telefone,
			input.SenhaHash,
			input.CodigoHash,
			input.CodigoExpiraEm,
			input.Email,
		)

		if err != nil {
			return mapError(err)
		}

		if affected, _ := result.RowsAffected(); affected > 0 {
			return nil
		}

		_, err = r.DB.ExecContext(
			ctx,
			`
			INSERT INTO users_temp (
				nome,
				email,
				telefone,
				senha_hash,
				codigo_hash,
				codigo_expira_em,
				tentativas
			)
			VALUES (?, ?, ?, ?, ?, ?, 0)
			`,
			input.Nome,
			input.Email,
			input.Telefone,
			input.SenhaHash,
			input.CodigoHash,
			input.CodigoExpiraEm,
		)

		if err == nil {
			return nil
		}

		if mapError(err) != ErrDuplicate {
			return mapError(err)
		}
	}

	return errors.New("não foi possível salvar o cadastro pendente")
}

func (r *UserTempRepository) ConsumirTentativa(
	ctx context.Context,
	id uint64,
	max int,
) (bool, error) {

	result, err := r.DB.ExecContext(
		ctx,
		`
		UPDATE users_temp
		SET tentativas = tentativas + 1
		WHERE id = ?
		  AND tentativas < ?
		`,
		id,
		max,
	)

	if err != nil {
		return false, mapError(err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return affected == 1, nil
}

func (r *UserTempRepository) Remover(
	ctx context.Context,
	id uint64,
) error {

	_, err := r.DB.ExecContext(
		ctx,
		`DELETE FROM users_temp WHERE id = ?`,
		id,
	)

	return mapError(err)
}

func (r *UserTempRepository) RemoverExpirados(
	ctx context.Context,
	antes time.Time,
) (int64, error) {

	result, err := r.DB.ExecContext(
		ctx,
		`
		DELETE FROM users_temp
		WHERE codigo_expira_em < ?
		`,
		antes,
	)

	if err != nil {
		return 0, mapError(err)
	}

	return result.RowsAffected()
}