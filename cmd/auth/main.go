package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ricardo-platform/auth/internal/api"
	"github.com/ricardo-platform/auth/internal/config"
	"github.com/ricardo-platform/auth/internal/database"
	"github.com/ricardo-platform/auth/internal/mailer"
	"github.com/ricardo-platform/auth/internal/ratelimit"
	"github.com/ricardo-platform/auth/internal/repository"
	"github.com/ricardo-platform/auth/internal/security"
	"github.com/ricardo-platform/auth/internal/service"
)

const (
	serverPort     = "8080"
	codeTTL        = 15 * time.Minute
	janitorInterval = 10 * time.Minute
)

func main() {
	if err := run(); err != nil {
		slog.Error("auth encerrado com erro", "err", err)
		os.Exit(1)
	}
}

func run() error {

	// --------------------------------------------------
	// CONFIG
	// --------------------------------------------------

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := slog.New(
		slog.NewTextHandler(os.Stdout, nil),
	)

	// --------------------------------------------------
	// CONTEXTO
	// --------------------------------------------------

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	// --------------------------------------------------
	// BANCO
	// --------------------------------------------------

	db, err := database.Connect(ctx, cfg)
	if err != nil {
		return errors.New(
			"erro ao conectar no MySQL: " + err.Error(),
		)
	}
	defer db.Close()

	log.Info(
		"conexão com MySQL OK",
		"banco",
		cfg.DBName,
	)

	if err := database.Migrate(ctx, db); err != nil {
		return err
	}

	log.Info("schema verificado")

	// --------------------------------------------------
	// REPOSITÓRIOS
	// --------------------------------------------------

	users := repository.NewUserRepository(db)

	pending := repository.NewUserTempRepository(db)

	recoveries := repository.NewPasswordRecoveryRepository(db)

	// --------------------------------------------------
	// EMAIL
	// --------------------------------------------------

	smtpMailer, err := mailer.NewSMTP(cfg)
	if err != nil {
		return err
	}

	mail := mailer.NewAsync(
		smtpMailer,
		log,
		20,
	)

	// --------------------------------------------------
	// SEGURANÇA
	// --------------------------------------------------

	// --------------------------------------------------
// SEGURANÇA
// --------------------------------------------------

	codes, err := security.NewCodes(codeTTL)
	if err != nil {
		return err
	}
	// --------------------------------------------------
	// LIMITES
	// --------------------------------------------------

	ipLimiter := ratelimit.New(
		30,
		time.Minute,
	)

	sendLimiter := ratelimit.New(
		3,
		10*time.Minute,
	)

	loginLimiter := ratelimit.New(
		10,
		15*time.Minute,
	)

	passwordLimiter := ratelimit.New(
		5,
		15*time.Minute,
	)

	// --------------------------------------------------
	// SERVIÇOS
	// --------------------------------------------------

	registerService := service.NewRegisterService(
		users,
		pending,
		codes,
		mail,
		sendLimiter,
		cfg.DevReturnCode,
	)

	verifyService := service.NewVerificationService(
		users,
		pending,
		codes,
	)

	loginService := service.NewLoginService(
		users,
		loginLimiter,
	)

	recoveryService := service.NewRecoveryService(
		users,
		recoveries,
		codes,
		mail,
		sendLimiter,
		cfg.DevReturnCode,
	)

	accountService := service.NewAccountService(
		users,
		passwordLimiter,
	)

	// --------------------------------------------------
	// API
	// --------------------------------------------------

	handler := api.New(api.Deps{
		Log: log,
		DB:  db,

		Register: registerService,
		Verify:   verifyService,
		Login:    loginService,
		Recovery: recoveryService,
		Accounts: accountService,

		IPLimiter: ipLimiter,

		CORSOrigins: cfg.CORSOrigins,
		TrustProxy:  cfg.TrustProxy,
	})

	// --------------------------------------------------
	// LIMPEZA
	// --------------------------------------------------

	go janitor(
		ctx,
		log,
		janitorInterval,
		func(ctx context.Context) {

			now := time.Now()

			// ------------------------------------------
			// USERS TEMP
			// ------------------------------------------

			if n, err := pending.RemoverExpirados(
				ctx,
				now,
			); err != nil {

				log.Error(
					"limpeza users_temp",
					"err",
					err,
				)

			} else if n > 0 {

				log.Info(
					"cadastros pendentes expirados removidos",
					"total",
					n,
				)
			}

			// ------------------------------------------
			// RECUPERAÇÃO DE SENHA
			// ------------------------------------------

			if n, err := recoveries.RemoverExpirados(
				ctx,
				now,
			); err != nil {

				log.Error(
					"limpeza password_recovery_temp",
					"err",
					err,
				)

			} else if n > 0 {

				log.Info(
					"recuperações expiradas removidas",
					"total",
					n,
				)
			}

			// ------------------------------------------
			// RATE LIMITS
			// ------------------------------------------

			ipLimiter.Cleanup()
			sendLimiter.Cleanup()
			loginLimiter.Cleanup()
			passwordLimiter.Cleanup()
		},
	)

	// --------------------------------------------------
	// SERVIDOR
	// --------------------------------------------------

	server := &http.Server{
		Addr:              ":" + serverPort,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	errCh := make(chan error, 1)

	go func() {

		log.Info(
			"servidor iniciado",
			"addr",
			"http://localhost"+server.Addr,
		)

		errCh <- server.ListenAndServe()
	}()

	// --------------------------------------------------
	// ENCERRAMENTO
	// --------------------------------------------------

	select {

	case err := <-errCh:

		if !errors.Is(
			err,
			http.ErrServerClosed,
		) {
			return err
		}

	case <-ctx.Done():

		log.Info("encerrando...")
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(
		shutdownCtx,
	); err != nil {
		return err
	}

	mail.Wait(10 * time.Second)

	return nil
}

func janitor(
	ctx context.Context,
	log *slog.Logger,
	every time.Duration,
	fn func(context.Context),
) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {

		select {

		case <-ctx.Done():
			return

		case <-ticker.C:

			func() {

				defer func() {

					if recovered := recover(); recovered != nil {

						log.Error(
							"panic no janitor",
							"recover",
							recovered,
						)
					}
				}()

				fn(ctx)
			}()
		}
	}
}