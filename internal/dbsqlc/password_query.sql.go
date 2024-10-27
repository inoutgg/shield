// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: password_query.sql

package dbsqlc

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const createUserPasswordCredential = `-- name: CreateUserPasswordCredential :exec
INSERT INTO shield_user_credentials
  (id, name, user_id, user_credential_key, user_credential_secret)
VALUES
  (
    $1::UUID,
    'password',
    $2::UUID,
    $3,
    $4
  )
`

type CreateUserPasswordCredentialParams struct {
	ID                   uuid.UUID
	UserID               uuid.UUID
	UserCredentialKey    string
	UserCredentialSecret string
}

func (q *Queries) CreateUserPasswordCredential(ctx context.Context, db DBTX, arg CreateUserPasswordCredentialParams) error {
	_, err := db.Exec(ctx, createUserPasswordCredential,
		arg.ID,
		arg.UserID,
		arg.UserCredentialKey,
		arg.UserCredentialSecret,
	)
	return err
}

const deleteExpiredPasswordResetTokens = `-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM shield_password_reset_tokens WHERE expires_at < now() RETURNING id
`

func (q *Queries) DeleteExpiredPasswordResetTokens(ctx context.Context, db DBTX) error {
	_, err := db.Exec(ctx, deleteExpiredPasswordResetTokens)
	return err
}

const findPasswordResetToken = `-- name: FindPasswordResetToken :one
SELECT id, created_at, updated_at, is_used, token, expires_at, user_id
FROM shield_password_reset_tokens
WHERE token = $1
LIMIT 1 AND expires_at > now()
`

func (q *Queries) FindPasswordResetToken(ctx context.Context, db DBTX, token string) (ShieldPasswordResetToken, error) {
	row := db.QueryRow(ctx, findPasswordResetToken, token)
	var i ShieldPasswordResetToken
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.IsUsed,
		&i.Token,
		&i.ExpiresAt,
		&i.UserID,
	)
	return i, err
}

const findUserWithPasswordCredentialByEmail = `-- name: FindUserWithPasswordCredentialByEmail :one
WITH
  credential AS (
    SELECT user_credential_key, user_credential_secret, user_id
    FROM shield_user_credentials
    WHERE name = 'password' AND user_credential_key = $1
  ),
  "user" AS (
    SELECT id, created_at, updated_at, email, is_email_verified
    FROM shield_users
    WHERE email = $1
  )
SELECT "user".id, "user".created_at, "user".updated_at, "user".email, "user".is_email_verified, credential.user_credential_secret AS password_hash
FROM
  credential
  -- validate that the credential and user has the same email address.
  JOIN "user"
    ON credential.user_id = "user".id
`

type FindUserWithPasswordCredentialByEmailRow struct {
	ID              uuid.UUID
	CreatedAt       pgtype.Timestamp
	UpdatedAt       pgtype.Timestamp
	Email           string
	IsEmailVerified bool
	PasswordHash    string
}

func (q *Queries) FindUserWithPasswordCredentialByEmail(ctx context.Context, db DBTX, email string) (FindUserWithPasswordCredentialByEmailRow, error) {
	row := db.QueryRow(ctx, findUserWithPasswordCredentialByEmail, email)
	var i FindUserWithPasswordCredentialByEmailRow
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.IsEmailVerified,
		&i.PasswordHash,
	)
	return i, err
}

const markPasswordResetTokenAsUsed = `-- name: MarkPasswordResetTokenAsUsed :exec
UPDATE shield_password_reset_tokens
SET is_used = TRUE
WHERE token = $1
`

func (q *Queries) MarkPasswordResetTokenAsUsed(ctx context.Context, db DBTX, token string) error {
	_, err := db.Exec(ctx, markPasswordResetTokenAsUsed, token)
	return err
}

const upsertPasswordCredentialByUserID = `-- name: UpsertPasswordCredentialByUserID :exec
WITH
  credential AS (
    INSERT INTO shield_user_credentials
      (id, name, user_id, user_credential_key, user_credential_secret)
    VALUES
      (
        $1::UUID,
        'password',
        $2::UUID,
        $3,
        $4
      )
    ON CONFLICT (name, user_credential_key) DO UPDATE
      SET user_credential_secret = $4
    RETURNING id
  )
SELECT id
FROM credential
`

type UpsertPasswordCredentialByUserIDParams struct {
	ID                   uuid.UUID
	UserID               uuid.UUID
	UserCredentialKey    string
	UserCredentialSecret string
}

func (q *Queries) UpsertPasswordCredentialByUserID(ctx context.Context, db DBTX, arg UpsertPasswordCredentialByUserIDParams) error {
	_, err := db.Exec(ctx, upsertPasswordCredentialByUserID,
		arg.ID,
		arg.UserID,
		arg.UserCredentialKey,
		arg.UserCredentialSecret,
	)
	return err
}

const upsertPasswordResetToken = `-- name: UpsertPasswordResetToken :one
WITH
  token AS (
    INSERT INTO shield_password_reset_tokens
      (id, user_id, token, expires_at, is_used)
    VALUES
      ($1::UUID, $2, $3, $4, FALSE)
    ON CONFLICT (user_id, is_used) DO UPDATE
      SET expires_at = greatest(
        excluded.expires_at,
        shield_password_reset_tokens.expires_at
      )
    RETURNING token, id, expires_at
  )
SELECT token, id, expires_at
FROM token
`

type UpsertPasswordResetTokenParams struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Token     string
	ExpiresAt pgtype.Timestamp
}

type UpsertPasswordResetTokenRow struct {
	Token     string
	ID        uuid.UUID
	ExpiresAt pgtype.Timestamp
}

func (q *Queries) UpsertPasswordResetToken(ctx context.Context, db DBTX, arg UpsertPasswordResetTokenParams) (UpsertPasswordResetTokenRow, error) {
	row := db.QueryRow(ctx, upsertPasswordResetToken,
		arg.ID,
		arg.UserID,
		arg.Token,
		arg.ExpiresAt,
	)
	var i UpsertPasswordResetTokenRow
	err := row.Scan(&i.Token, &i.ID, &i.ExpiresAt)
	return i, err
}
