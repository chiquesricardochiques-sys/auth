package repository

import (
	"database/sql"
	"errors"

	"github.com/go-sql-driver/mysql"
)

var (
	ErrNotFound  = errors.New("registro não encontrado")
	ErrDuplicate = errors.New("registro duplicado")
)

func mapError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}

	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return ErrDuplicate
	}

	return err
}