-- name: TestFindUserByID :one
SELECT * FROM shield_users WHERE id = @id LIMIT 1;

-- name: TestFindAllUsers :many
SELECT * FROM shield_users;

-- name: TestCreateUser :one
INSERT INTO shield_users (email, is_email_verified)
VALUES (@email, @is_email_verified)
RETURNING *;
