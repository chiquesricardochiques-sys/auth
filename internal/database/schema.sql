-- Schema do RICARDO AUTH SERVICE (idempotente: CREATE TABLE IF NOT EXISTS).
-- Executado no start quando AUTH_AUTO_MIGRATE=true.
-- Em bancos que já têm essas tabelas nada é alterado (veja o README).

CREATE TABLE IF NOT EXISTS users (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  nome             VARCHAR(120)  NOT NULL,
  email            VARCHAR(254)  NOT NULL,
  telefone         VARCHAR(30)   NULL,
  senha_hash       VARCHAR(255)  NULL,
  status           VARCHAR(20)   NOT NULL DEFAULT 'ativo',
  email_verificado TINYINT(1)    NOT NULL DEFAULT 0,
  created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users_temp (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  nome             VARCHAR(120)  NOT NULL,
  email            VARCHAR(254)  NOT NULL,
  telefone         VARCHAR(30)   NULL,
  senha_hash       VARCHAR(255)  NOT NULL,
  codigo_hash      VARCHAR(64)   NOT NULL,
  codigo_expira_em DATETIME      NOT NULL,
  tentativas       INT           NOT NULL DEFAULT 0,
  created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_users_temp_email (email),
  KEY idx_users_temp_expira (codigo_expira_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS password_recovery_temp (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  email            VARCHAR(254)  NOT NULL,
  senha_hash       VARCHAR(255)  NOT NULL,
  codigo_hash      VARCHAR(64)   NOT NULL,
  codigo_expira_em DATETIME      NOT NULL,
  tentativas       INT           NOT NULL DEFAULT 0,
  created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_recovery_email (email),
  KEY idx_recovery_expira (codigo_expira_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CREATE TABLE IF NOT EXISTS auth_sessions (
--   id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
--   token_hash CHAR(64)        NOT NULL,
--   user_id    BIGINT UNSIGNED NOT NULL,
--   created_at DATETIME        NOT NULL,
--   expires_at DATETIME        NOT NULL,
--   ip         VARCHAR(45)     NULL,
--   user_agent VARCHAR(255)    NULL,
--   UNIQUE KEY uq_auth_sessions_token (token_hash),
--   KEY idx_auth_sessions_user (user_id),
--   KEY idx_auth_sessions_expires (expires_at)
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
