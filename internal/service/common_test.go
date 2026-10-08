package service

import (
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	ok := map[string]string{
		"  Ricardo@Exemplo.com ": "ricardo@exemplo.com",
		"a.b+tag@dominio.com.br": "a.b+tag@dominio.com.br",
	}
	for in, want := range ok {
		got, err := normalizeEmail(in)
		if err != nil || got != want {
			t.Errorf("normalizeEmail(%q) = %q, %v; queria %q", in, got, err, want)
		}
	}

	bad := []string{"", "sem-arroba", "a@b", "Nome <a@b.com>", "a@b.com\r\nBcc: x@y.com", strings.Repeat("a", 260) + "@b.com"}
	for _, in := range bad {
		if _, err := normalizeEmail(in); err == nil {
			t.Errorf("normalizeEmail(%q) deveria falhar", in)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if validatePassword("") == nil || validatePassword("curta") == nil {
		t.Error("senha vazia/curta deveria falhar")
	}
	if validatePassword(strings.Repeat("a", 73)) == nil {
		t.Error("senha com mais de 72 bytes deveria falhar")
	}
	if err := validatePassword("senha-boa-123"); err != nil {
		t.Errorf("senha válida recusada: %v", err)
	}
}

func TestNormalizePhone(t *testing.T) {
	v := "+55 (19) 99999-0000"
	if p, err := normalizePhone(&v); err != nil || p == nil {
		t.Errorf("telefone válido recusado: %v", err)
	}
	empty := "  "
	if p, err := normalizePhone(&empty); err != nil || p != nil {
		t.Error("telefone vazio deveria virar nil")
	}
	bad := "abc"
	if _, err := normalizePhone(&bad); err == nil {
		t.Error("telefone inválido deveria falhar")
	}
}
