-- name: TestCreatePassword :one
INSERT INTO shield_user_credentials
  (id, name, user_id, user_credential_key, user_credential_secret)
VALUES
  (
    @id::UUID,
    'password',
    @user_id::UUID,
    @user_credential_key,
    @user_credential_secret
  )
RETURNING *;
