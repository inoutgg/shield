-- name: UpsertPasswordCredentialByUserID :exec
WITH
  credential AS (
    INSERT INTO shield_user_credentials
      (id, name, user_id, user_credential_key, user_credential_secret)
    VALUES
      (@id, 'password', @user_id, @user_credential_key, @user_credential_secret)
    ON CONFLICT (name, user_credential_key) DO UPDATE
      SET user_credential_secret = @user_credential_secret
    RETURNING id
  )
SELECT *
FROM credential;

-- name: FindUserWithPasswordCredentialByEmail :one
SELECT u.*, credential.user_credential_secret AS password_hash
FROM
  shield_users AS u
  JOIN shield_user_credentials AS credential
    ON credential.user_id = u.id
    AND credential.name = 'password'
    AND credential.user_credential_key = @email
WHERE u.email = @email;

-- name: FindUserWithPasswordCredentialByUserID :one
SELECT shield_user.*, credential.user_credential_secret AS password_hash
FROM
  shield_users AS shield_user
  LEFT JOIN shield_user_credentials AS credential
    ON credential.user_id = shield_user.id
    AND credential.name = 'password'
    AND credential.user_credential_key = shield_user.email
WHERE shield_user.id = @user_id;

-- name: ChangePasswordCredentialEmailByUserID :exec
UPDATE shield_user_credentials
SET user_credential_key = @email
WHERE user_id = @user_id AND name = 'password';

-- name: UpsertPasswordResetToken :one
WITH
  token AS (
    INSERT INTO shield_password_reset_tokens
      (id, user_id, token, expires_at, is_used)
    VALUES
      (@id, @user_id, @token, @expires_at, FALSE)
    ON CONFLICT (user_id, is_used) DO UPDATE
      SET expires_at = greatest(
        excluded.expires_at,
        shield_password_reset_tokens.expires_at
      )
    RETURNING token, id, expires_at
  )
SELECT *
FROM token;

-- name: FindPasswordResetToken :one
SELECT *
FROM shield_password_reset_tokens
WHERE token = @token
LIMIT 1 AND expires_at > now();

-- name: MarkPasswordResetTokenAsUsed :exec
UPDATE shield_password_reset_tokens
SET is_used = TRUE
WHERE token = @token;

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM shield_password_reset_tokens WHERE expires_at < now() RETURNING id;
