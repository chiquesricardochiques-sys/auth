// Package apperr define os erros de aplicação usados pelas camadas do AUTH.
//
// O service devolve *Error e a camada HTTP traduz o erro para JSON.
package apperr

import "errors"

type Error struct {
	Status  int
	Code    string
	Message string
	Err     error // causa interna (nunca vai para o cliente)
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}

	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

func New(status int, code, message string) *Error {
	return &Error{
		Status:  status,
		Code:    code,
		Message: message,
	}
}

// Internal embrulha um erro inesperado
// (banco, rand, SMTP, etc.).
func Internal(err error) *Error {
	return &Error{
		Status:  500,
		Code:    "INTERNAL_ERROR",
		Message: "Erro interno. Tente novamente mais tarde.",
		Err:     err,
	}
}

// From converte qualquer error em *Error.
func From(err error) *Error {
	var e *Error

	if errors.As(err, &e) {
		return e
	}

	return Internal(err)
}

var (
	// --------------------------------------------------
	// Validação
	// --------------------------------------------------

	InvalidJSON = New(
		400,
		"INVALID_JSON",
		"JSON inválido.",
	)

	NameRequired = New(
		400,
		"NAME_REQUIRED",
		"O nome é obrigatório.",
	)

	NameTooLong = New(
		400,
		"NAME_TOO_LONG",
		"O nome deve ter no máximo 120 caracteres.",
	)

	EmailRequired = New(
		400,
		"EMAIL_REQUIRED",
		"O email é obrigatório.",
	)

	InvalidEmail = New(
		400,
		"INVALID_EMAIL",
		"Email inválido.",
	)

	InvalidPhone = New(
		400,
		"INVALID_PHONE",
		"Telefone inválido.",
	)

	PasswordRequired = New(
		400,
		"PASSWORD_REQUIRED",
		"A senha é obrigatória.",
	)

	PasswordTooShort = New(
		400,
		"PASSWORD_TOO_SHORT",
		"A senha deve ter pelo menos 8 caracteres.",
	)

	PasswordTooLong = New(
		400,
		"PASSWORD_TOO_LONG",
		"A senha deve ter no máximo 72 bytes.",
	)

	PasswordMismatch = New(
		400,
		"PASSWORD_MISMATCH",
		"As senhas não coincidem.",
	)

	CodeRequired = New(
		400,
		"CODE_REQUIRED",
		"O código é obrigatório.",
	)

	// --------------------------------------------------
	// Conta
	// --------------------------------------------------

	AccountExists = New(
		409,
		"ACCOUNT_ALREADY_EXISTS",
		"Já existe uma conta com este email.",
	)

	AccountNotFound = New(
		404,
		"ACCOUNT_NOT_FOUND",
		"Conta não encontrada.",
	)

	AccountInactive = New(
		403,
		"ACCOUNT_INACTIVE",
		"A conta está inativa.",
	)

	InvalidCredentials = New(
		401,
		"INVALID_CREDENTIALS",
		"Email ou senha inválidos.",
	)

	WrongPassword = New(
		403,
		"WRONG_PASSWORD",
		"Senha incorreta.",
	)

	// --------------------------------------------------
	// Verificação de email
	// --------------------------------------------------

	VerificationNotFound = New(
		400,
		"VERIFICATION_NOT_FOUND",
		"Não existe uma verificação pendente para este email.",
	)

	CodeExpired = New(
		400,
		"CODE_EXPIRED",
		"O código de verificação expirou.",
	)

	InvalidCode = New(
		400,
		"INVALID_CODE",
		"Código inválido ou expirado.",
	)

	TooManyAttempts = New(
		429,
		"TOO_MANY_ATTEMPTS",
		"Muitas tentativas. Solicite um novo código.",
	)

	// --------------------------------------------------
	// Limitação
	// --------------------------------------------------

	RateLimited = New(
		429,
		"RATE_LIMITED",
		"Muitas requisições. Aguarde um pouco e tente novamente.",
	)

	// --------------------------------------------------
	// Email
	// --------------------------------------------------

	MailBusy = New(
		503,
		"MAIL_UNAVAILABLE",
		"Não foi possível enviar o email agora. Tente novamente.",
	)

	// --------------------------------------------------
	// HTTP
	// --------------------------------------------------

	NotFound = New(
		404,
		"NOT_FOUND",
		"Rota não encontrada.",
	)

	MethodNotAllowed = New(
		405,
		"METHOD_NOT_ALLOWED",
		"Método não permitido.",
	)
)