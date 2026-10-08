package service

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ricardo-platform/auth/internal/apperr"
)


type ClientInfo struct {
	IP        string
	UserAgent string
}

const (
	MaxCodeAttempts = 5

	minPasswordLen   = 8
	maxPasswordBytes = 72
)

var phoneRe = regexp.MustCompile(`^\+?[0-9 ()\-]{8,20}$`)

func normalizeEmail(raw string) (string, error) {

	email := strings.ToLower(strings.TrimSpace(raw))

	if email == "" {
		return "", apperr.EmailRequired
	}

	if len(email) > 254 {
		return "", apperr.InvalidEmail
	}

	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", apperr.InvalidEmail
	}

	_, domain, _ := strings.Cut(email, "@")

	if !strings.Contains(domain, ".") {
		return "", apperr.InvalidEmail
	}

	return email, nil
}

func validatePassword(password string) error {

	switch {
	case password == "":
		return apperr.PasswordRequired

	case utf8.RuneCountInString(password) < minPasswordLen:
		return apperr.PasswordTooShort

	case len(password) > maxPasswordBytes:
		return apperr.PasswordTooLong
	}

	return nil
}

func normalizeName(raw string) (string, error) {

	name := strings.TrimSpace(raw)

	if name == "" {
		return "", apperr.NameRequired
	}

	if utf8.RuneCountInString(name) > 120 {
		return "", apperr.NameTooLong
	}

	return name, nil
}

func normalizePhone(phone *string) (*string, error) {

	if phone == nil {
		return nil, nil
	}

	value := strings.TrimSpace(*phone)

	if value == "" {
		return nil, nil
	}

	if !phoneRe.MatchString(value) {
		return nil, apperr.InvalidPhone
	}

	return &value, nil
}