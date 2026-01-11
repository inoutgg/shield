-- ============================================================================
-- shield_users
-- ============================================================================

CREATE TABLE IF NOT EXISTS shield_users (
  id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  email VARCHAR(256) NOT NULL,
  is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (id),
  UNIQUE (email)
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_users ON shield_users;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_users
BEFORE UPDATE ON shield_users
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_user_email_verification_tokens
-- ============================================================================

CREATE UNLOGGED TABLE IF NOT EXISTS shield_user_email_verification_tokens (
  id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_used BOOLEAN NOT NULL DEFAULT FALSE,
  token VARCHAR(16) NOT NULL,
  email VARCHAR(256) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  PRIMARY KEY (user_id, id),
  UNIQUE (email, is_used),
  UNIQUE (token),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_email_verification_tokens ON shield_user_email_verification_tokens;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_user_email_verification_tokens
BEFORE UPDATE ON shield_user_email_verification_tokens
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_user_credentials
-- ============================================================================

CREATE TABLE IF NOT EXISTS shield_user_credentials (
  id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  name VARCHAR(256) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  user_credential_key VARCHAR(256) NOT NULL, -- can be SSO user ID, email, etc.
  user_credential_secret VARCHAR(4095) NOT NULL, -- can SSO token, password hash, etc.
  PRIMARY KEY (user_id, id),
  UNIQUE (name, user_credential_key),
  UNIQUE (name, user_id),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_credentials ON shield_user_credentials;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_user_credentials
BEFORE UPDATE ON shield_user_credentials
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_password_reset_tokens
-- ============================================================================

CREATE UNLOGGED TABLE IF NOT EXISTS shield_password_reset_tokens (
  id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_used BOOLEAN NOT NULL DEFAULT FALSE,
  token VARCHAR(16) NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  PRIMARY KEY (user_id, id),
  UNIQUE (token),
  UNIQUE (user_id, is_used),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE,
  CHECK (expires_at > CURRENT_TIMESTAMP),
  CHECK (expires_at > created_at)
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_password_reset_tokens ON shield_password_reset_tokens;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_password_reset_tokens
BEFORE UPDATE ON shield_password_reset_tokens
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_user_sessions
-- ============================================================================

CREATE UNLOGGED TABLE IF NOT EXISTS shield_user_sessions (
  id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  evicted_by VARCHAR(64) NULL,
  is_mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (user_id, id),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE,
  FOREIGN KEY (evicted_by) REFERENCES shield_users (id),
  CHECK (expires_at > CURRENT_TIMESTAMP),
  CHECK (expires_at > created_at)
);

CREATE INDEX sus_id_idx ON shield_user_sessions USING HASH (id);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_sessions ON shield_user_sessions;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_user_sessions
BEFORE UPDATE ON shield_user_sessions
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_recovery_codes
-- ============================================================================

CREATE TABLE IF NOT EXISTS shield_recovery_codes (
  id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_id VARCHAR(64) NOT NULL,
  recovery_code_hash VARCHAR(4095) NOT NULL,
  is_consumable BOOL NOT NULL DEFAULT TRUE,
  evicted_by VARCHAR(64) NULL,
  evicted_at TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  FOREIGN KEY (evicted_by) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

CREATE INDEX src_user_id_idx ON shield_recovery_codes (user_id);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_recovery_codes ON shield_recovery_codes;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_recovery_codes
BEFORE UPDATE ON shield_recovery_codes
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_user_mfas
-- ============================================================================

CREATE TABLE IF NOT EXISTS shield_user_mfas (
  id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  name VARCHAR(256) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  UNIQUE (user_id, name),
  FOREIGN KEY (user_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CHECK (name IN ('mfa_passkey', 'mfa_email', 'mfa_otp'))
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_mfas ON shield_user_mfas;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_user_mfas
BEFORE UPDATE ON shield_user_mfas
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_workspaces
-- ============================================================================

CREATE TABLE IF NOT EXISTS shield_workspaces (
  id VARCHAR(64) NOT NULL,
  owned_by VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  name VARCHAR(256) NOT NULL,
  slug VARCHAR(64) NOT NULL,

  PRIMARY KEY (id),
  UNIQUE (slug),

  FOREIGN KEY (owned_by) REFERENCES shield_users (id)
    ON UPDATE CASCADE
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspaces ON shield_workspaces;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_workspaces
BEFORE UPDATE ON shield_workspaces
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_workspace_teams
-- ============================================================================

CREATE TABLE IF NOT EXISTS shield_workspace_teams (
  id VARCHAR(64) NOT NULL,
  workspace_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_system BOOLEAN NOT NULL DEFAULT FALSE,
  name VARCHAR(256) NOT NULL,
  handle VARCHAR(64) NOT NULL,
  -- metadata may contain arbitrary app-defined information, for instance ACL, etc.
  metadata JSONB NULL,

  PRIMARY KEY (workspace_id, id),
  UNIQUE(workspace_id, handle),

  FOREIGN KEY (workspace_id) REFERENCES shield_workspaces (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspace_teams ON shield_workspace_teams;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_workspace_teams
BEFORE UPDATE ON shield_workspace_teams
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_workspace_team_members
-- ============================================================================

CREATE TABLE IF NOT EXISTS shield_workspace_team_members (
  id VARCHAR(64) NOT NULL,
  workspace_id VARCHAR(64) NOT NULL,
  team_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  member_id VARCHAR(64) NOT NULL,
  PRIMARY KEY (workspace_id, team_id, member_id),
  FOREIGN KEY (member_id) REFERENCES shield_users (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  FOREIGN KEY (workspace_id) REFERENCES shield_workspaces (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES shield_workspace_teams (workspace_id, id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspace_team_members ON shield_workspace_team_members;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_workspace_team_members
BEFORE UPDATE ON shield_workspace_team_members
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- shield_workspace_membership_invitations
-- ============================================================================

CREATE TABLE IF NOT EXISTS shield_workspace_membership_invitations (
  id VARCHAR(64) NOT NULL,
  workspace_id VARCHAR(64) NOT NULL,
  team_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  member_email VARCHAR(256) NOT NULL,
  status VARCHAR(256) NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  accepted_at TIMESTAMP WITH TIME ZONE NULL,
  rejected_at TIMESTAMP WITH TIME ZONE NULL,

  CHECK (status IN ('pending', 'accepted', 'rejected')),

  PRIMARY KEY (workspace_id, team_id, id),
  FOREIGN KEY (workspace_id) REFERENCES shield_workspaces (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES shield_workspace_teams (workspace_id, id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspace_membership_invitations ON shield_workspace_membership_invitations;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_workspace_membership_invitations
BEFORE UPDATE ON shield_workspace_membership_invitations
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

-- ============================================================================
-- Functions
-- ============================================================================

CREATE OR REPLACE FUNCTION shield_fn_autoupdate_updated_at()
RETURNS TRIGGER
AS $$
BEGIN
    IF NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
        RETURN NEW;
    END IF;

    IF (NEW IS DISTINCT FROM OLD) THEN
        NEW.updated_at = NOW();
    END IF;

    RETURN NEW;
END;
$$
LANGUAGE plpgsql;
