package security

import (
	"testing"
	"time"
)

func TestCodeRoundTrip(t *testing.T) {
	c := NewCodes("segredo-de-teste-com-mais-de-32-caracteres", 15*time.Minute)

	code, err := c.Generate("a@b.com", "account_verification")
	if err != nil {
		t.Fatal(err)
	}
	if len(code.Plain) != 6 {
		t.Fatalf("código deveria ter 6 dígitos, veio %q", code.Plain)
	}
	if !c.Check("a@b.com", "account_verification", code.Plain, code.Hash) {
		t.Fatal("código correto foi recusado")
	}
	if c.Check("a@b.com", "account_verification", "000000x", code.Hash) {
		t.Fatal("código errado foi aceito")
	}
	// o mesmo código não vale para outro email nem para outra finalidade
	if c.Check("outro@b.com", "account_verification", code.Plain, code.Hash) {
		t.Fatal("código aceito para outro email")
	}
	if c.Check("a@b.com", "password_recovery", code.Plain, code.Hash) {
		t.Fatal("código aceito para outra finalidade")
	}
}

func TestPasswordAndToken(t *testing.T) {
	h, err := HashPassword("minha-senha-123")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword("minha-senha-123", h) || CheckPassword("outra", h) {
		t.Fatal("verificação de senha incorreta")
	}

	tok, err := NewToken()
	if err != nil || len(tok) != 64 {
		t.Fatalf("token inválido: %q %v", tok, err)
	}
	if HashToken(tok) == tok || len(HashToken(tok)) != 64 {
		t.Fatal("hash do token inválido")
	}
}
