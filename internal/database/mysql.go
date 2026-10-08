
package database

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/ricardo-platform/auth/internal/config"
)

//go:embed schema.sql
var schema string

// Connect abre e testa a conexão com o MySQL.
func Connect(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	mysqlConfig := mysql.NewConfig()
	mysqlConfig.User = cfg.DBUser
	mysqlConfig.Passwd = cfg.DBPassword
	mysqlConfig.Net = "tcp"
	mysqlConfig.Addr = cfg.DBHost + ":" + cfg.DBPort
	mysqlConfig.DBName = cfg.DBName
	mysqlConfig.ParseTime = true
	mysqlConfig.Collation = "utf8mb4_unicode_ci"
	mysqlConfig.Timeout = 5 * time.Second
	mysqlConfig.ReadTimeout = 10 * time.Second
	mysqlConfig.WriteTimeout = 10 * time.Second

	db, err := sql.Open("mysql", mysqlConfig.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("abrir conexão MySQL: %w", err)
	}

	// Pool de conexões.
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	// Testa a conexão com o banco.
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("conectar ao MySQL: %w", err)
	}

	return db, nil
}

// Migrate cria as tabelas definidas no schema.sql.
// As instruções devem ser compatíveis com a divisão por ponto e vírgula.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("migração: conexão com o banco não configurada")
	}

	for i, stmt := range splitStatements(schema) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf(
				"migração %d falhou: %w\nSQL: %s",
				i+1,
				err,
				stmt,
			)
		}
	}

	return nil
}

// splitStatements separa o schema.sql em instruções SQL.
// Não use ponto e vírgula dentro de strings ou procedimentos SQL.
func splitStatements(sqlText string) []string {
	var statements []string

	for _, part := range strings.Split(sqlText, ";") {
		var lines []string

		for _, line := range strings.Split(part, "\n") {
			line = strings.TrimSpace(line)

			if line == "" || strings.HasPrefix(line, "--") {
				continue
			}

			lines = append(lines, line)
		}

		if len(lines) == 0 {
			continue
		}

		statement := strings.TrimSpace(strings.Join(lines, "\n"))
		if statement != "" {
			statements = append(statements, statement)
		}
	}

	return statements
}