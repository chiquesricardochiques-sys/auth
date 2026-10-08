// Package config carrega a configuração a partir de variáveis de ambiente
// e de um arquivo .env opcional. Nenhum segredo tem valor padrão.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env  string // "development" | "production"
	Port string

	// Banco de dados
	DBHost      string
	DBPort      string
	DBUser      string
	DBPassword  string
	DBName      string
	AutoMigrate bool

	// Códigos de verificação
	CodeSecret    string
	CodeTTL       time.Duration
	DevReturnCode bool // Devolve o código na resposta; nunca em produção.

	// Email
	MailMode     string // "smtp" | "log"
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	SMTPTLS      string // "starttls" | "ssl" | "none"
	EmailFrom    string

	// Sessão
	SessionTTL   time.Duration
	CookieName   string
	CookieDomain string
	CookieSecure bool

	// HTTP
	CORSOrigins []string
	TrustProxy  bool

	// Serviços autorizados a chamar /introspect: nome -> chave.
	ServiceKeys map[string]string
}

func (c Config) IsProduction() bool {
	return c.Env == "production"
}

func Load() (Config, error) {
	// O ambiente do sistema operacional tem prioridade sobre o .env.
	loadDotEnv(getEnv("AUTH_ENV_FILE", ".env"))

	var problems []string

	need := func(name string) string {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			problems = append(
				problems,
				"variável obrigatória ausente: "+name,
			)
		}
		return value
	}

	cfg := Config{
		Env:         strings.ToLower(strings.TrimSpace(getEnv("AUTH_ENV", "development"))),
		Port:        strings.TrimSpace(getEnv("AUTH_PORT", "8080")),
		DBHost:      strings.TrimSpace(getEnv("DB_HOST", "localhost")),
		DBPort:      strings.TrimSpace(getEnv("DB_PORT", "3306")),
		DBUser:      strings.TrimSpace(getEnv("DB_USER", "root")),
		DBName:      strings.TrimSpace(getEnv("DB_NAME", "ricardo_platform")),
		AutoMigrate: readBool("AUTH_AUTO_MIGRATE", true, &problems),
		CookieName:  strings.TrimSpace(getEnv("AUTH_COOKIE_NAME", "auth_session")),
		CookieDomain: strings.TrimSpace(
			os.Getenv("AUTH_COOKIE_DOMAIN"),
		),
		TrustProxy: readBool("AUTH_TRUST_PROXY", false, &problems),
	}

	// Ambiente
	switch cfg.Env {
	case "development", "production":
	default:
		problems = append(
			problems,
			"AUTH_ENV deve ser development ou production",
		)
	}

	// Porta HTTP
	validatePort("AUTH_PORT", cfg.Port, &problems)

	// Banco de dados
	validatePort("DB_PORT", cfg.DBPort, &problems)

	if cfg.DBHost == "" {
		problems = append(problems, "DB_HOST não pode ficar vazio")
	}
	if cfg.DBUser == "" {
		problems = append(problems, "DB_USER não pode ficar vazio")
	}
	if cfg.DBName == "" {
		problems = append(problems, "DB_NAME não pode ficar vazio")
	}

	cfg.DBPassword = need("DB_PASSWORD")
	cfg.CodeSecret = need("AUTH_CODE_SECRET")

	if cfg.CodeSecret != "" && len(cfg.CodeSecret) < 32 {
		problems = append(
			problems,
			"AUTH_CODE_SECRET deve ter pelo menos 32 bytes",
		)
	}

	// Tempo de validade dos códigos.
	codeTTLMinutes := readPositiveInt(
		"AUTH_CODE_TTL_MINUTES",
		15,
		&problems,
	)
	cfg.CodeTTL = time.Duration(codeTTLMinutes) * time.Minute

	cfg.DevReturnCode = readBool(
		"AUTH_DEV_RETURN_CODE",
		false,
		&problems,
	)

	// Sessões.
	sessionTTLHours := readPositiveInt(
		"AUTH_SESSION_TTL_HOURS",
		720,
		&problems,
	)
	cfg.SessionTTL = time.Duration(sessionTTLHours) * time.Hour

	cfg.CookieSecure = readBool(
		"AUTH_COOKIE_SECURE",
		cfg.IsProduction(),
		&problems,
	)

	if cfg.CookieName == "" {
		problems = append(problems, "AUTH_COOKIE_NAME não pode ficar vazio")
	}

	// CORS: lista separada por vírgulas.
	for _, origin := range strings.Split(
		os.Getenv("AUTH_CORS_ORIGINS"),
		",",
	) {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			cfg.CORSOrigins = append(cfg.CORSOrigins, origin)
		}
	}

	// Email / SMTP.
	cfg.SMTPHost = strings.TrimSpace(os.Getenv("EMAIL_SMTP_HOST"))
	cfg.SMTPUser = strings.TrimSpace(os.Getenv("EMAIL_SMTP_USER"))
	cfg.SMTPPassword = os.Getenv("EMAIL_SMTP_PASSWORD")
	cfg.SMTPPort = strings.TrimSpace(getEnv("EMAIL_SMTP_PORT", "587"))
	cfg.EmailFrom = strings.TrimSpace(
		getEnv("EMAIL_FROM", cfg.SMTPUser),
	)

	cfg.SMTPTLS = strings.ToLower(
		strings.TrimSpace(os.Getenv("EMAIL_SMTP_TLS")),
	)

	if cfg.SMTPTLS == "" {
		// Compatibilidade com a variável antiga EMAIL_SMTP_SECURE.
		legacySecure := readBool(
			"EMAIL_SMTP_SECURE",
			false,
			&problems,
		)

		if legacySecure {
			cfg.SMTPTLS = "ssl"
		} else {
			cfg.SMTPTLS = "starttls"
		}
	}

	switch cfg.SMTPTLS {
	case "starttls", "ssl", "none":
	default:
		problems = append(
			problems,
			"EMAIL_SMTP_TLS deve ser starttls, ssl ou none",
		)
	}

	cfg.MailMode = strings.ToLower(
		strings.TrimSpace(os.Getenv("AUTH_MAIL_MODE")),
	)

	if cfg.MailMode == "" {
		if cfg.SMTPHost != "" && cfg.SMTPUser != "" {
			cfg.MailMode = "smtp"
		} else {
			cfg.MailMode = "log"
		}
	}

	switch cfg.MailMode {
	case "smtp":
		if cfg.SMTPHost == "" {
			problems = append(
				problems,
				"EMAIL_SMTP_HOST é obrigatório quando AUTH_MAIL_MODE=smtp",
			)
		}

		if cfg.SMTPUser == "" {
			problems = append(
				problems,
				"EMAIL_SMTP_USER é obrigatório quando AUTH_MAIL_MODE=smtp",
			)
		}

		if cfg.SMTPPassword == "" {
			problems = append(
				problems,
				"EMAIL_SMTP_PASSWORD é obrigatório quando AUTH_MAIL_MODE=smtp",
			)
		}

		if cfg.EmailFrom == "" {
			problems = append(
				problems,
				"EMAIL_FROM é obrigatório quando AUTH_MAIL_MODE=smtp",
			)
		}

		validatePort("EMAIL_SMTP_PORT", cfg.SMTPPort, &problems)

	case "log":
	default:
		problems = append(
			problems,
			"AUTH_MAIL_MODE deve ser smtp ou log",
		)
	}

	// Chaves de serviços.
	// Formato: AUTH_SERVICE_KEYS=servico:chave,outro:outra_chave
	cfg.ServiceKeys = make(map[string]string)

	for _, pair := range strings.Split(
		os.Getenv("AUTH_SERVICE_KEYS"),
		",",
	) {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		name, key, ok := strings.Cut(pair, ":")
		name = strings.TrimSpace(name)
		key = strings.TrimSpace(key)

		if !ok || name == "" || len(key) < 24 {
			problems = append(
				problems,
				"AUTH_SERVICE_KEYS deve usar nome:chave, com chave de pelo menos 24 bytes",
			)
			continue
		}

		if _, exists := cfg.ServiceKeys[name]; exists {
			problems = append(
				problems,
				"nome de serviço duplicado em AUTH_SERVICE_KEYS: "+name,
			)
			continue
		}

		cfg.ServiceKeys[name] = key
	}

	// Regras de produção.
	if cfg.IsProduction() {
		if cfg.MailMode == "log" {
			problems = append(
				problems,
				"AUTH_MAIL_MODE=log não é permitido em produção",
			)
		}

		if cfg.DevReturnCode {
			problems = append(
				problems,
				"AUTH_DEV_RETURN_CODE não é permitido em produção",
			)
		}
	}

	if len(problems) > 0 {
		return Config{}, errors.New(
			"configuração inválida:\n - " +
				strings.Join(problems, "\n - "),
		)
	}

	return cfg, nil
}

// readBool lê um booleano e registra valores inválidos.
func readBool(
	name string,
	fallback bool,
	problems *[]string,
) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))

	switch value {
	case "":
		return fallback
	case "1", "true", "yes", "sim":
		return true
	case "0", "false", "no", "nao", "não":
		return false
	default:
		*problems = append(
			*problems,
			fmt.Sprintf(
				"%s deve ser true ou false; valor inválido",
				name,
			),
		)
		return fallback
	}
}

// readPositiveInt lê um inteiro positivo e registra valores inválidos.
func readPositiveInt(
	name string,
	fallback int,
	problems *[]string,
) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		*problems = append(
			*problems,
			fmt.Sprintf("%s deve ser um inteiro maior que zero", name),
		)
		return fallback
	}

	return value
}

// validatePort valida uma porta TCP entre 1 e 65535.
func validatePort(
	name string,
	raw string,
	problems *[]string,
) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		*problems = append(
			*problems,
			fmt.Sprintf("%s deve ser uma porta entre 1 e 65535", name),
		)
	}
}

// getEnv retorna a variável de ambiente ou o valor padrão.
func getEnv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// loadDotEnv lê KEY=VALUE sem sobrescrever variáveis já existentes
// no ambiente do sistema operacional.
func loadDotEnv(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		if _, exists := os.LookupEnv(key); exists {
			continue
		}

		_ = os.Setenv(key, parseEnvValue(value))
	}
}

// parseEnvValue interpreta o valor à direita de KEY=VALUE.
//
// - Valores entre aspas mantêm o conteúdo interno.
// - Valores sem aspas ignoram comentários iniciados por espaço + #.
func parseEnvValue(value string) string {
	value = strings.TrimSpace(value)

	if value == "" || value[0] == '#' {
		return ""
	}

	if value[0] == '"' || value[0] == '\'' {
		if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
			return value[1 : 1+end]
		}

		return value[1:]
	}

	for _, separator := range []string{" #", "\t#"} {
		if index := strings.Index(value, separator); index >= 0 {
			value = value[:index]
		}
	}

	return strings.TrimSpace(value)
}

