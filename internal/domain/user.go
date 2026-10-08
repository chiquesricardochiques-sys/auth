package domain

import "time"

const StatusAtivo = "ativo"

type User struct {
	ID              uint64  `json:"id"`
	Nome            string  `json:"nome"`
	Email           string  `json:"email"`
	Telefone        *string `json:"telefone,omitempty"`
	SenhaHash       *string `json:"-"`
	Status          string  `json:"status"`
	EmailVerificado bool    `json:"email_verificado"`
}

type UserInput struct {
	Nome            string
	Email           string
	Telefone        *string
	SenhaHash       *string
	Status          string
	EmailVerificado bool
}

// UserTemp é um cadastro aguardando confirmação do código enviado por email.
type UserTemp struct {
	ID             uint64
	Nome           string
	Email          string
	Telefone       *string
	SenhaHash      string
	CodigoHash     string
	CodigoExpiraEm time.Time
	Tentativas     int
}

type UserTempInput struct {
	Nome           string
	Email          string
	Telefone       *string
	SenhaHash      string
	CodigoHash     string
	CodigoExpiraEm time.Time
}

// PasswordRecovery é uma redefinição de senha aguardando o código.
type PasswordRecovery struct {
	ID             uint64
	Email          string
	SenhaHash      string
	CodigoHash     string
	CodigoExpiraEm time.Time
	Tentativas     int
}

type PasswordRecoveryInput struct {
	Email          string
	SenhaHash      string
	CodigoHash     string
	CodigoExpiraEm time.Time
}