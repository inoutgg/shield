-- name: CreateUser :exec
INSERT INTO shield_users (id, email)
VALUES (@id::UUID, @email);

-- name: FindUserByID :one
SELECT * FROM shield_users WHERE id = @id::UUID LIMIT 1;

-- name: FindUserByEmail :one
SELECT * FROM shield_users WHERE email = @email LIMIT 1;

-- name: ChangeUserEmailByID :exec
UPDATE shield_users
SET
  email = @email,
  is_email_verified = FALSE
WHERE id = @id;

-- name: UpsertEmailVerificationToken :one
WITH
  token AS (
    INSERT INTO shield_user_email_verification_tokens
      (id, user_id, token, is_used)
    VALUES
      (@id::UUID, @user_id, @token, @expires_at, FALSE)
    ON CONFLICT (user_id, is_used) DO NOTHING
    RETURNING token, id
  )
SELECT *
FROM token;

-- name: MarkUserEmailVerificationTokenAsUsed :exec
UPDATE shield_user_email_verification_tokens
SET is_used = TRUE
WHERE token = @token;
