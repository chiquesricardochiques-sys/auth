package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/ricardo-platform/auth/internal/config"
)

// SMTPMailer usa apenas a biblioteca padrão (net/smtp), sem dependências extras.
type SMTPMailer struct {
	host, port, user, password, tlsMode string
	from                                *mail.Address
}

func NewSMTP(cfg config.Config) (*SMTPMailer, error) {
	from, err := mail.ParseAddress(cfg.EmailFrom)
	if err != nil {
		return nil, fmt.Errorf("EMAIL_FROM inválido: %w", err)
	}

	return &SMTPMailer{
		host:     cfg.SMTPHost,
		port:     cfg.SMTPPort,
		user:     cfg.SMTPUser,
		password: cfg.SMTPPassword,
		tlsMode:  cfg.SMTPTLS,
		from:     from,
	}, nil
}

func (m *SMTPMailer) SendCode(ctx context.Context, to, code string, purpose Purpose, ttl time.Duration) error {
	subject, text, htmlBody := render(code, purpose, ttl)

	msg, err := m.buildMessage(to, subject, text, htmlBody)
	if err != nil {
		return err
	}

	return m.deliver(ctx, to, msg)
}

func (m *SMTPMailer) deliver(ctx context.Context, to string, msg []byte) error {
	addr := net.JoinHostPort(m.host, m.port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsCfg := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	var err error

	if m.tlsMode == "ssl" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("conexão SMTP: %w", err)
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("cliente SMTP: %w", err)
	}
	defer c.Close()

	if m.tlsMode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("o servidor SMTP não oferece STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	if m.user != "" {
		// PlainAuth se recusa a enviar a senha sem TLS (exceto em localhost).
		if err := c.Auth(smtp.PlainAuth("", m.user, m.password, m.host)); err != nil {
			return fmt.Errorf("autenticação SMTP: %w", err)
		}
	}

	if err := c.Mail(m.from.Address); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("escrita da mensagem: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("fim da mensagem: %w", err)
	}

	return c.Quit()
}

func (m *SMTPMailer) buildMessage(to, subject, text, htmlBody string) ([]byte, error) {
	// `to` já foi validado por net/mail e normalizado pelo service; mesmo assim,
	// recusa qualquer quebra de linha para impedir injeção de cabeçalhos.
	if strings.ContainsAny(to, "\r\n") {
		return nil, errors.New("destinatário inválido")
	}

	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	msgID := hex.EncodeToString(idBytes)
	boundary := "b_" + hex.EncodeToString(idBytes)

	domain := "localhost"
	if _, d, ok := strings.Cut(m.from.Address, "@"); ok {
		domain = d
	}

	var buf bytes.Buffer

	header := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }

	header("From", m.from.String())
	header("To", to)
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", time.Now().Format(time.RFC1123Z))
	header("Message-ID", fmt.Sprintf("<%s@%s>", msgID, domain))
	header("MIME-Version", "1.0")
	header("Content-Type", fmt.Sprintf("multipart/alternative; boundary=%s", boundary))
	buf.WriteString("\r\n")

	part := func(contentType, body string) error {
		fmt.Fprintf(&buf, "--%s\r\n", boundary)
		fmt.Fprintf(&buf, "Content-Type: %s; charset=UTF-8\r\n", contentType)
		buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")

		qp := quotedprintable.NewWriter(&buf)
		if _, err := qp.Write([]byte(body)); err != nil {
			return err
		}
		if err := qp.Close(); err != nil {
			return err
		}
		buf.WriteString("\r\n")
		return nil
	}

	if err := part("text/plain", text); err != nil {
		return nil, err
	}
	if err := part("text/html", htmlBody); err != nil {
		return nil, err
	}

	fmt.Fprintf(&buf, "--%s--\r\n", boundary)

	return buf.Bytes(), nil
}
