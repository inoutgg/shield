-- name: GetUserMFAsByUserID :many
SELECT * FROM shield_user_mfas WHERE user_id = @user_id;

-- name: CreateUserMFA :one
INSERT INTO shield_user_mfas
  (user_id, name)
VALUES
  (@user_id, @name)
RETURNING *;
