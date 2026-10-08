# RICARDO AUTH SERVICE

API que centraliza as contas de todos os seus sites/apps, como um provedor de email:
uma conta só, criada aqui, usada em qualquer lugar. Go + MySQL + SMTP, API REST/JSON.

## Rodando

```bash
cp .env.example .env      # preencha DB_PASSWORD e AUTH_CODE_SECRET
go run ./cmd/auth
go test ./...
```

Sem `AUTH_MAIL_MODE=smtp` o código de verificação aparece no **log** do servidor
(só desenvolvimento). Para testar sem olhar o log, use `AUTH_DEV_RETURN_CODE=true`.

## Estrutura

```
cmd/auth/main.go          liga tudo (config, banco, serviços, servidor, shutdown)
internal/config           variáveis de ambiente + .env (sem segredos padrão)
internal/api              rotas, middlewares (CORS, rate limit, log), JSON
internal/service          regras de negócio (register, verify, login, recovery, account, session)
internal/repository       SQL (users, users_temp, password_recovery_temp, auth_sessions)
internal/security         bcrypt, HMAC dos códigos, tokens
internal/mailer           SMTP (net/smtp), modo log, envio assíncrono
internal/database         conexão + schema.sql (migração idempotente)
internal/apperr           erros com status HTTP e código
internal/ratelimit        limitador em memória
```

`go.mod`/`go.sum` continuam os mesmos: nenhuma dependência nova.

## Endpoints

| Método | Rota | Auth | O que faz |
|---|---|---|---|
| GET | `/api/auth/health` | — | status (testa o banco) |
| POST | `/api/auth/register` | — | `{nome,email,telefone?,senha}` → envia código por email |
| POST | `/api/auth/verify` | — | `{email,codigo}` → cria a conta |
| POST | `/api/auth/login` | — | `{email,senha}` → `session.token` (e cookie) |
| POST | `/api/auth/recovery` | — | `{email,senha,confirmar_senha}` → envia código |
| POST | `/api/auth/recovery/verify` | — | `{email,codigo}` → aplica a nova senha |
| GET | `/api/auth/me` | sessão | dados da conta |
| PUT | `/api/auth/account` | sessão | `{nome,telefone?}` |
| PUT | `/api/auth/password` | sessão | `{senha_atual,nova_senha}` |
| DELETE | `/api/auth/account` | sessão | `{senha}` → exclui a conta |
| POST | `/api/auth/logout` | sessão | encerra a sessão atual |
| POST | `/api/auth/logout-all` | sessão | encerra todas as sessões |
| POST | `/api/auth/introspect` | `X-Service-Key` | `{token}` → `{active, user}` |

Sessão = `Authorization: Bearer <token>` ou cookie `auth_session`.
Erros: `{"success":false,"code":"INVALID_CREDENTIALS","message":"..."}`.

### Login centralizado nos outros sites

O backend de cada app (CorteRapido, PersonaLab, financeiro...) recebe o token do usuário
e pergunta ao AUTH se ele vale:

```bash
curl -X POST http://localhost:8080/api/auth/introspect \
  -H "X-Service-Key: <chave do app>" -H "Content-Type: application/json" \
  -d '{"token":"<token do usuário>"}'
# {"success":true,"active":true,"client":"corterapido","user":{...},"expires_at":"..."}
```

Cada app tem a sua chave em `AUTH_SERVICE_KEYS=corterapido:...,personalab:...`.
Para sites em subdomínios do mesmo domínio, `AUTH_COOKIE_DOMAIN=.seudominio.com` faz o cookie valer em todos.

## O que mudou em relação à versão anterior

**Segurança**
- Segredos saíram do código: sem senha padrão de banco/SMTP. O programa não inicia se faltar variável obrigatória.
- O código de verificação **não é mais devolvido na resposta**; vai por email (SMTP real com TLS). Antes, qualquer pessoa confirmava qualquer email sem acessar a caixa de entrada.
- Tentativas de código agora **são limitadas** (5, reservadas de forma atômica). Antes o contador subia mas nunca bloqueava: 1.000.000 de combinações era força bruta trivial.
- Código guardado como **HMAC** com `AUTH_CODE_SECRET`, amarrado ao email e à finalidade (antes: SHA-256 puro, reversível em segundos).
- Sessões saíram da memória: ficam em `auth_sessions`, com **expiração** (30 dias) e só o **hash** do token. Reiniciar o servidor não derruba mais todo mundo, e tokens não valiam para sempre.
- Redefinir ou trocar a senha encerra as outras sessões.
- Recovery não revela se o email existe (resposta e tempo iguais); login não revela conta inexistente por tempo de resposta nem status antes de conferir a senha.
- Rate limit: por IP nas rotas sensíveis, por IP+email no login, por email no envio de códigos.
- Validação de email, senha (8 a 72 bytes, limite do bcrypt), nome e telefone; corpo limitado a 64 KB; bcrypt cost 12.
- Timeouts no servidor, CORS por lista de origens, cabeçalhos de segurança, shutdown gracioso.

**Bugs**
- `UpdateAccount` retornava "usuário não encontrado" quando você salvava os mesmos dados (o MySQL devolve 0 linhas afetadas).
- Erros internos eram engolidos sem log; agora vão para o log, e o cliente recebe só uma mensagem genérica.
- DSN do MySQL montado com `Sprintf` quebrava com `@` ou `/` na senha; agora usa `mysql.Config`.
- Cadastro/recuperação pendentes expirados nunca eram limpos; um janitor roda a cada 10 minutos.

**Estrutura**
- Services devolvem erros tipados (`apperr`) em vez de `map[string]interface{}`; o handler não precisa mais adivinhar status.
- `context` em todas as queries; método guard virou padrão do `ServeMux` (`"POST /api/..."`), com 405/404 em JSON.
- Pacotes de `integrations` (github/google/microsoft/sms/whatsapp) eram stubs que não faziam nada: removidos. O email virou o pacote `mailer`.

## Compatibilidade e migração

- Mesmas rotas, mesmos campos de entrada e quase os mesmos de saída. Diferenças: `codigo` só aparece com `AUTH_DEV_RETURN_CODE=true`; `register` repetido devolve **409** (antes 400); a sessão ganhou `expires_at`; login de conta inativa devolve **403**.
- Porta padrão agora é **8080** (era 4000); variável `EMAIL_SMTP_SECURE` continua aceita, mas o novo é `EMAIL_SMTP_TLS`.
- Quem estiver no meio de um cadastro ou recuperação na hora do deploy precisa pedir outro código (o formato do hash mudou).
- Sessões antigas (em memória) deixam de existir: todos fazem login de novo uma vez.
- `AUTH_AUTO_MIGRATE=true` só cria o que falta, inclusive `auth_sessions` (nome diferente de uma eventual tabela `sessions` antiga, para não colidir). Em banco **já existente**, adicione os índices únicos de email (falha se houver duplicados, o que também mostra um problema real):

```sql
ALTER TABLE users                   ADD UNIQUE KEY uq_users_email (email);
ALTER TABLE users_temp              ADD UNIQUE KEY uq_users_temp_email (email);
ALTER TABLE password_recovery_temp  ADD UNIQUE KEY uq_recovery_email (email);
```

## Antes de subir para produção

1. **Troque as credenciais que estavam no `config.go`**: a senha do MySQL e a senha de app do Gmail (revogue a antiga em Conta Google → Segurança → Senhas de app). Se o código já passou por algum repositório, considere-as vazadas.
2. `AUTH_ENV=production`, `AUTH_MAIL_MODE=smtp`, HTTPS na frente (nginx/caddy) com `AUTH_TRUST_PROXY=true`.
3. Os limitadores e o envio de email ficam em memória do processo: com mais de uma instância, o limite vale por instância (para escalar, mover o rate limit para Redis).
