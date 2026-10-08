package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// NewToken gera um token de sessão opaco (256 bits).
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken é o que vai para o banco: se a tabela vazar, os tokens não servem.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
