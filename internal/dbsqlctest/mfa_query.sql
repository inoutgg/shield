-- name: GetUserMFAsByUserID :many
SELECT * FROM shield_user_mfas WHERE user_id = @user_id;

-- name: CreateUserMFA :one
INSERT INTO shield_user_mfas
  (id, user_id, name)
VALUES
  (@id, @user_id, @name)
RETURNING *;
