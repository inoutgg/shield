-- migration: 20250711123140_mfa.sql

CREATE TABLE IF NOT EXISTS shield_user_mfas (
  id UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  name VARCHAR(255) NOT NULL,
  user_id UUID NOT NULL,
  UNIQUE (user_id, name),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CHECK (name IN ('mfa_passkey', 'mfa_email', 'mfa_otp'))
);

ALTER TABLE shield_user_sessions ADD COLUMN is_mfa_required BOOLEAN NOT NULL DEFAULT FALSE;

---- create above / drop below ----

DROP TABLE IF EXISTS shield_user_mfas;

ALTER TABLE shield_user_sessions DROP COLUMN is_completed;
