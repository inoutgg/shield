-- migration: 20250629163225_initial_schema.sql.sql

CREATE TABLE IF NOT EXISTS shield_users (
  id UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  email VARCHAR(255) NOT NULL,
  is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (id),
  UNIQUE (email)
);

CREATE TABLE IF NOT EXISTS shield_user_email_verification_tokens (
  id UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_used BOOLEAN NOT NULL DEFAULT FALSE,
  token VARCHAR(16) NOT NULL,
  email VARCHAR(255) NOT NULL,
  user_id UUID NOT NULL,
  PRIMARY KEY (user_id, id),
  UNIQUE (email, is_used),
  UNIQUE (token),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS shield_user_credentials (
  id UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  name VARCHAR(255) NOT NULL,
  user_id UUID NOT NULL,
  user_credential_key VARCHAR(255) NOT NULL, -- can be SSO user ID, email, etc.
  user_credential_secret VARCHAR(4095) NOT NULL, -- can SSO token, password hash, etc.
  PRIMARY KEY (user_id, id),
  UNIQUE (name, user_credential_key),
  UNIQUE (name, user_id),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS shield_password_reset_tokens (
  id UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_used BOOLEAN NOT NULL DEFAULT FALSE,
  token VARCHAR(16) NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  user_id UUID NOT NULL,
  PRIMARY KEY (user_id, id),
  UNIQUE (token),
  UNIQUE (user_id, is_used),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE,
  CHECK (expires_at > CURRENT_TIMESTAMP),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS shield_user_sessions (
  id UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  user_id UUID NOT NULL,
  evicted_by UUID NULL,
  PRIMARY KEY (user_id, id),
  UNIQUE (id),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE,
  FOREIGN KEY (evicted_by) REFERENCES shield_users (id),
  CHECK (expires_at > CURRENT_TIMESTAMP),
  CHECK (expires_at > created_at)
);

---- create above / drop below ----

DROP TABLE IF EXISTS shield_user_sessions;
DROP TABLE IF EXISTS shield_password_reset_tokens;
DROP TABLE IF EXISTS shield_user_credentials;
DROP TABLE IF EXISTS shield_user_email_verification_tokens;
DROP TABLE IF EXISTS shield_users;
