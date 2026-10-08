package security

import (
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

var (
	dummyOnce sync.Once
	dummyHash []byte
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// BurnCPU gasta o mesmo tempo de uma verificação real. Usado quando a conta
// não existe, para o tempo de resposta não revelar se o email está cadastrado.
func BurnCPU(password string) {
	dummyOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcryptCost)
	})
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}
