-- name: CreateUserPasskeyCredential :exec
INSERT INTO shield_user_credentials
  (id, name, user_id, user_credential_key, user_credential_secret)
VALUES
  (@id, 'passkey', @user_id, @user_credential_key, @user_credential_secret);

-- name: FindUserWithPasskeyCredentialByEmail :one
SELECT u.*, credential.user_credential_secret::JSON AS user_credential
FROM
  shield_users AS u
  JOIN shield_user_credentials AS credential
    ON credential.user_id = u.id
    AND credential.name = 'passkey'
    AND credential.user_credential_key = @email
WHERE u.email = @email;
