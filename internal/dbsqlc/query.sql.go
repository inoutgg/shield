// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: query.sql

package dbsqlc

import (
	"context"

	"github.com/google/uuid"
)

const changeUserEmailByID = `-- name: ChangeUserEmailByID :exec
UPDATE users
SET
  email = $1,
  is_email_verified = FALSE
WHERE id = $2
`

type ChangeUserEmailByIDParams struct {
	Email string
	ID    uuid.UUID
}

func (q *Queries) ChangeUserEmailByID(ctx context.Context, db DBTX, arg ChangeUserEmailByIDParams) error {
	_, err := db.Exec(ctx, changeUserEmailByID, arg.Email, arg.ID)
	return err
}

const createUser = `-- name: CreateUser :exec
INSERT INTO users (id, email)
VALUES ($1::UUID, $2)
`

type CreateUserParams struct {
	ID    uuid.UUID
	Email string
}

func (q *Queries) CreateUser(ctx context.Context, db DBTX, arg CreateUserParams) error {
	_, err := db.Exec(ctx, createUser, arg.ID, arg.Email)
	return err
}

const findUserByEmail = `-- name: FindUserByEmail :one
SELECT id, created_at, updated_at, email, is_email_verified FROM users WHERE email = $1 LIMIT 1
`

func (q *Queries) FindUserByEmail(ctx context.Context, db DBTX, email string) (User, error) {
	row := db.QueryRow(ctx, findUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.IsEmailVerified,
	)
	return i, err
}

const findUserByID = `-- name: FindUserByID :one
SELECT id, created_at, updated_at, email, is_email_verified FROM users WHERE id = $1::UUID LIMIT 1
`

func (q *Queries) FindUserByID(ctx context.Context, db DBTX, id uuid.UUID) (User, error) {
	row := db.QueryRow(ctx, findUserByID, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.IsEmailVerified,
	)
	return i, err
}

const markUserEmailVerificationTokenAsUsed = `-- name: MarkUserEmailVerificationTokenAsUsed :exec
UPDATE user_email_verification_tokens
SET is_used = TRUE
WHERE token = $1
`

func (q *Queries) MarkUserEmailVerificationTokenAsUsed(ctx context.Context, db DBTX, token string) error {
	_, err := db.Exec(ctx, markUserEmailVerificationTokenAsUsed, token)
	return err
}

const upsertEmailVerificationToken = `-- name: UpsertEmailVerificationToken :one
WITH
  token AS (
    INSERT INTO user_email_verification_tokens
      (id, user_id, token, is_used)
    VALUES
      ($1::UUID, $2, $3, $4, FALSE)
    ON CONFLICT (user_id, is_used) DO NOTHING
    RETURNING token, id
  )
SELECT token, id
FROM token
`

type UpsertEmailVerificationTokenParams struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Token     string
	ExpiresAt bool
}

type UpsertEmailVerificationTokenRow struct {
	Token string
	ID    uuid.UUID
}

func (q *Queries) UpsertEmailVerificationToken(ctx context.Context, db DBTX, arg UpsertEmailVerificationTokenParams) (UpsertEmailVerificationTokenRow, error) {
	row := db.QueryRow(ctx, upsertEmailVerificationToken,
		arg.ID,
		arg.UserID,
		arg.Token,
		arg.ExpiresAt,
	)
	var i UpsertEmailVerificationTokenRow
	err := row.Scan(&i.Token, &i.ID)
	return i, err
}
