package mailer

import (
	"fmt"
	"html"
	"time"
)

func render(code string, purpose Purpose, ttl time.Duration) (subject, text, htmlBody string) {
	var finalidade string

	switch purpose {
	case PurposeRecovery:
		subject = "Redefinição de senha - RICARDO AUTH"
		finalidade = "redefinir a senha da sua conta"
	default:
		subject = "Confirme seu cadastro - RICARDO AUTH"
		finalidade = "confirmar o cadastro da sua conta"
	}

	minutos := int(ttl.Minutes())

	text = fmt.Sprintf(
		"Seu código de verificação é: %s\n\n"+
			"Use-o para %s. Ele expira em %d minutos.\n\n"+
			"Se você não solicitou isso, ignore este email.\n\nRICARDO AUTH\n",
		code, finalidade, minutos,
	)

	htmlBody = fmt.Sprintf(
		`<div style="font-family:Arial,sans-serif;max-width:420px">`+
			`<h2>RICARDO AUTH</h2>`+
			`<p>Seu código de verificação é:</p>`+
			`<p style="font-size:32px;letter-spacing:6px;font-weight:bold">%s</p>`+
			`<p>Use-o para %s. Ele expira em <strong>%d minutos</strong>.</p>`+
			`<p style="color:#666">Se você não solicitou isso, ignore este email.</p>`+
			`</div>`,
		html.EscapeString(code), html.EscapeString(finalidade), minutos,
	)

	return subject, text, htmlBody
}
