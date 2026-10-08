// Package mailer envia os códigos de verificação por email.
package mailer

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type Purpose string

const (
	PurposeVerification Purpose = "account_verification"
	PurposeRecovery     Purpose = "password_recovery"
)

type Mailer interface {
	SendCode(ctx context.Context, to, code string, purpose Purpose, ttl time.Duration) error
}

// ---------------------------------------------------------------------------
// LogMailer: só desenvolvimento. Escreve o código no log em vez de enviar.
// ---------------------------------------------------------------------------

type LogMailer struct {
	Log *slog.Logger
}

func (m LogMailer) SendCode(_ context.Context, to, code string, purpose Purpose, _ time.Duration) error {
	m.Log.Warn("MODO LOG (somente desenvolvimento): email não enviado",
		"to", to, "purpose", string(purpose), "code", code)
	return nil
}

// ---------------------------------------------------------------------------
// Async: envia em goroutine para a resposta HTTP não esperar o SMTP.
// ---------------------------------------------------------------------------

var ErrBusy = errors.New("fila de envio de email cheia")

type Async struct {
	inner   Mailer
	log     *slog.Logger
	sem     chan struct{}
	wg      sync.WaitGroup
	timeout time.Duration
}

func NewAsync(inner Mailer, log *slog.Logger, maxInFlight int) *Async {
	return &Async{
		inner:   inner,
		log:     log,
		sem:     make(chan struct{}, maxInFlight),
		timeout: 30 * time.Second,
	}
}

func (a *Async) SendCode(_ context.Context, to, code string, purpose Purpose, ttl time.Duration) error {
	select {
	case a.sem <- struct{}{}:
	default:
		return ErrBusy
	}

	a.wg.Add(1)

	go func() {
		defer a.wg.Done()
		defer func() { <-a.sem }()

		// contexto próprio: a requisição HTTP que originou o envio já terminou
		ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
		defer cancel()

		if err := a.inner.SendCode(ctx, to, code, purpose, ttl); err != nil {
			a.log.Error("falha ao enviar código por email", "purpose", string(purpose), "to", maskEmail(to), "err", err)
			return
		}

		a.log.Info("código enviado por email (aceito pelo servidor SMTP)", "purpose", string(purpose), "to", maskEmail(to))
	}()

	return nil
}

// Wait espera os envios em andamento (usado no shutdown).
func (a *Async) Wait(timeout time.Duration) {
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// maskEmail esconde parte do endereço nos logs: ricardo@gmail.com -> r***@gmail.com
func maskEmail(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" {
		return "***"
	}
	return local[:1] + "***@" + domain
}