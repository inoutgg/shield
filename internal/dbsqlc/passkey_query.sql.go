// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: passkey_query.sql

package dbsqlc

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const createUserPasskeyCredential = `-- name: CreateUserPasskeyCredential :exec
INSERT INTO shield_user_credentials
  (id, name, user_id, user_credential_key, user_credential_secret)
VALUES
  (
    $1::UUID,
    'passkey',
    $2::UUID,
    $3,
    $4
  )
`

type CreateUserPasskeyCredentialParams struct {
	ID                   uuid.UUID
	UserID               uuid.UUID
	UserCredentialKey    string
	UserCredentialSecret string
}

func (q *Queries) CreateUserPasskeyCredential(ctx context.Context, db DBTX, arg CreateUserPasskeyCredentialParams) error {
	_, err := db.Exec(ctx, createUserPasskeyCredential,
		arg.ID,
		arg.UserID,
		arg.UserCredentialKey,
		arg.UserCredentialSecret,
	)
	return err
}

const findUserWithPasskeyCredentialByEmail = `-- name: FindUserWithPasskeyCredentialByEmail :one
WITH
  credential AS (
    SELECT user_credential_key, user_credential_secret, user_id
    FROM shield_user_credentials
    WHERE name = 'passkey' AND user_credential_key = $1
  ),
  "user" AS (
    SELECT id, created_at, updated_at, email, is_email_verified
    FROM shield_users
    WHERE email = $1
  )
SELECT "user".id, "user".created_at, "user".updated_at, "user".email, "user".is_email_verified, credential.user_credential_secret::JSON AS user_credential
FROM
  credential
  -- validate that the credential and user has the same email address.
  JOIN "user"
    ON credential.user_id = "user".id
`

type FindUserWithPasskeyCredentialByEmailRow struct {
	ID              uuid.UUID
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Email           string
	IsEmailVerified bool
	UserCredential  []byte
}

func (q *Queries) FindUserWithPasskeyCredentialByEmail(ctx context.Context, db DBTX, email string) (FindUserWithPasskeyCredentialByEmailRow, error) {
	row := db.QueryRow(ctx, findUserWithPasskeyCredentialByEmail, email)
	var i FindUserWithPasskeyCredentialByEmailRow
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.IsEmailVerified,
		&i.UserCredential,
	)
	return i, err
}
