package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

const codeSecretSize = 32

// Codes gera e valida códigos numéricos de 6 dígitos.
type Codes struct {
	secret []byte
	ttl    time.Duration
}

type Code struct {
	Plain     string
	Hash      string
	ExpiresAt time.Time
}

// NewCodes cria o gerador de códigos.
// O segredo é criado aleatoriamente na memória durante a inicialização.
func NewCodes(ttl time.Duration) (*Codes, error) {
	secret := make([]byte, codeSecretSize)

	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("não foi possível gerar segredo dos códigos: %w", err)
	}

	return &Codes{
		secret: secret,
		ttl:    ttl,
	}, nil
}

func (c *Codes) TTL() time.Duration {
	return c.ttl
}

func (c *Codes) Generate(email, purpose string) (Code, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return Code{}, err
	}

	plain := fmt.Sprintf("%06d", n.Int64())

	return Code{
		Plain:     plain,
		Hash:      c.Hash(email, purpose, plain),
		ExpiresAt: time.Now().Add(c.ttl),
	}, nil
}

func (c *Codes) Hash(email, purpose, code string) string {
	mac := hmac.New(sha256.New, c.secret)

	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(email))
	mac.Write([]byte{0})
	mac.Write([]byte(code))

	return hex.EncodeToString(mac.Sum(nil))
}

func (c *Codes) Check(email, purpose, code, hash string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(c.Hash(email, purpose, code)),
		[]byte(hash),
	) == 1
}