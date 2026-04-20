-- name: CreateUserSession :one
INSERT INTO shield_user_sessions (
  user_id,
  expires_at,
  is_mfa_required,
  impersonated_by
)
VALUES (@user_id, @expires_at, @is_mfa_required, @impersonated_by)
RETURNING id;

-- name: FindActiveSessionByID :one
SELECT *
FROM shield_user_sessions
WHERE id = @id AND expires_at > NOW()
LIMIT 1;

-- name: AllActiveSessions :many
SELECT *
FROM shield_user_sessions
WHERE user_id = @user_id AND expires_at > NOW();

-- name: ExpireSessionByID :one
UPDATE shield_user_sessions
SET expires_at = NOW()
WHERE id = @id
RETURNING id;

-- name: ExpireAllSessionsByUserID :many
UPDATE shield_user_sessions
SET
  expires_at = NOW(),
  evicted_by = @evicted_by
WHERE user_id = @user_id
RETURNING id;

-- name: ExpireSomeSessionsByUserID :many
UPDATE shield_user_sessions
SET
  expires_at = NOW(),
  evicted_by = @evicted_by
WHERE user_id = @user_id AND id != ANY (@session_ids::BIGINT[])
RETURNING id;
