-- migration: 20250818221228_updated_at.sql

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

---- INITIAL SCHEMA ----

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_users ON shield_users;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_users
BEFORE UPDATE ON shield_users
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_credentials ON shield_user_credentials;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_user_credentials
BEFORE UPDATE ON shield_user_credentials
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_email_verification_tokens ON shield_user_email_verification_tokens;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_user_email_verification_tokens
BEFORE UPDATE ON shield_user_email_verification_tokens
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_password_reset_tokens ON shield_password_reset_tokens;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_password_reset_tokens
BEFORE UPDATE ON shield_password_reset_tokens
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_sessions ON shield_user_sessions;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_user_sessions
BEFORE UPDATE ON shield_user_sessions
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

---- RECOVERY CODES ----

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_recovery_codes ON shield_recovery_codes;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_recovery_codes
BEFORE UPDATE ON shield_recovery_codes
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

---- MFA ----

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_mfas ON shield_user_mfas;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_user_mfas
BEFORE UPDATE ON shield_user_mfas
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

---- WORKSPACE ----

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspace_members ON shield_workspace_members;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_workspace_members
BEFORE UPDATE ON shield_workspace_members
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspace_membership_invitations ON shield_workspace_membership_invitations;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_workspace_membership_invitations
BEFORE UPDATE ON shield_workspace_membership_invitations
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspaces ON shield_workspaces;
CREATE TRIGGER shield_trigger_autoupdate_updated_at_shield_workspaces
BEFORE UPDATE ON shield_workspaces
FOR EACH ROW
EXECUTE FUNCTION shield_fn_autoupdate_updated_at();

---- create above / drop below ----

DROP FUNCTION IF EXISTS shield_fn_autoupdate_updated_at();

---- INITIAL SCHEMA ----

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_users ON shield_users;
DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_credentials ON shield_user_credentials;
DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_email_verification_tokens ON shield_user_email_verification_tokens;
DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_password_reset_tokens ON shield_password_reset_tokens;
DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_sessions ON shield_user_sessions;

---- RECOVERY CODES ----

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_recovery_codes ON shield_recovery_codes;

---- MFAs ----

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_user_mfas ON shield_user_mfas;

---- WORKSPACE ----

DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspace_members ON shield_workspace_members;
DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspace_membership_invitations ON shield_workspace_membership_invitations;
DROP TRIGGER IF EXISTS shield_trigger_autoupdate_updated_at_shield_workspaces ON shield_workspaces;
