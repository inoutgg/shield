-- name: TestFindUserByID :one
SELECT * FROM shield_users WHERE id = @id::UUID LIMIT 1;

-- name: TestFindAllUsers :many
SELECT * FROM shield_users;

-- name: TestCreateUser :one
INSERT INTO shield_users (id, email, is_email_verified)
VALUES (@id, @email, @is_email_verified) RETURNING *;
