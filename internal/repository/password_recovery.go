package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ricardo-platform/auth/internal/domain"
)

type PasswordRecoveryRepository struct {
	DB *sql.DB
}

func NewPasswordRecoveryRepository(db *sql.DB) *PasswordRecoveryRepository {
	return &PasswordRecoveryRepository{
		DB: db,
	}
}

func (r *PasswordRecoveryRepository) BuscarPorEmail(
	ctx context.Context,
	email string,
) (*domain.PasswordRecovery, error) {

	var recovery domain.PasswordRecovery

	err := r.DB.QueryRowContext(
		ctx,
		`
		SELECT
			id,
			email,
			senha_hash,
			codigo_hash,
			codigo_expira_em,
			tentativas
		FROM password_recovery_temp
		WHERE email = ?
		ORDER BY id DESC
		LIMIT 1
		`,
		email,
	).Scan(
		&recovery.ID,
		&recovery.Email,
		&recovery.SenhaHash,
		&recovery.CodigoHash,
		&recovery.CodigoExpiraEm,
		&recovery.Tentativas,
	)

	if err != nil {
		return nil, mapError(err)
	}

	return &recovery, nil
}

func (r *PasswordRecoveryRepository) Salvar(
	ctx context.Context,
	input domain.PasswordRecoveryInput,
) error {

	for tentativa := 0; tentativa < 2; tentativa++ {
		result, err := r.DB.ExecContext(
			ctx,
			`
			UPDATE password_recovery_temp
			SET
				senha_hash = ?,
				codigo_hash = ?,
				codigo_expira_em = ?,
				tentativas = 0
			WHERE email = ?
			`,
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
			INSERT INTO password_recovery_temp (
				email,
				senha_hash,
				codigo_hash,
				codigo_expira_em,
				tentativas
			)
			VALUES (?, ?, ?, ?, 0)
			`,
			input.Email,
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

	return errors.New("não foi possível salvar a recuperação pendente")
}

func (r *PasswordRecoveryRepository) ConsumirTentativa(
	ctx context.Context,
	id uint64,
	max int,
) (bool, error) {

	result, err := r.DB.ExecContext(
		ctx,
		`
		UPDATE password_recovery_temp
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

func (r *PasswordRecoveryRepository) Remover(
	ctx context.Context,
	id uint64,
) error {

	_, err := r.DB.ExecContext(
		ctx,
		`DELETE FROM password_recovery_temp WHERE id = ?`,
		id,
	)

	return mapError(err)
}

func (r *PasswordRecoveryRepository) RemoverPorEmail(
	ctx context.Context,
	email string,
) error {

	_, err := r.DB.ExecContext(
		ctx,
		`DELETE FROM password_recovery_temp WHERE email = ?`,
		email,
	)

	return mapError(err)
}

func (r *PasswordRecoveryRepository) RemoverExpirados(
	ctx context.Context,
	antes time.Time,
) (int64, error) {

	result, err := r.DB.ExecContext(
		ctx,
		`
		DELETE FROM password_recovery_temp
		WHERE codigo_expira_em < ?
		`,
		antes,
	)

	if err != nil {
		return 0, mapError(err)
	}

	return result.RowsAffected()
}