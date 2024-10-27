-- name: CreateUserPasskeyCredential :exec
INSERT INTO shield_user_credentials
  (id, name, user_id, user_credential_key, user_credential_secret)
VALUES
  (
    @id::UUID,
    'passkey',
    @user_id::UUID,
    @user_credential_key,
    @user_credential_secret
  );

-- name: FindUserWithPasskeyCredentialByEmail :one
WITH
  credential AS (
    SELECT user_credential_key, user_credential_secret, user_id
    FROM shield_user_credentials
    WHERE name = 'passkey' AND user_credential_key = @email
  ),
  "user" AS (
    SELECT *
    FROM shield_users
    WHERE email = @email
  )
SELECT "user".*, credential.user_credential_secret::JSON AS user_credential
FROM
  credential
  -- validate that the credential and user has the same email address.
  JOIN "user"
    ON credential.user_id = "user".id;
