// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: user_query.sql

package dbsqlctest

import (
	"context"

	"github.com/google/uuid"
)

const testCreateUser = `-- name: TestCreateUser :one
INSERT INTO shield_users (id, email, is_email_verified)
VALUES ($1, $2, $3) RETURNING id, created_at, updated_at, email, is_email_verified
`

type TestCreateUserParams struct {
	ID              uuid.UUID
	Email           string
	IsEmailVerified bool
}

func (q *Queries) TestCreateUser(ctx context.Context, db DBTX, arg TestCreateUserParams) (ShieldUser, error) {
	row := db.QueryRow(ctx, testCreateUser, arg.ID, arg.Email, arg.IsEmailVerified)
	var i ShieldUser
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.IsEmailVerified,
	)
	return i, err
}

const testFindAllUsers = `-- name: TestFindAllUsers :many
SELECT id, created_at, updated_at, email, is_email_verified FROM shield_users
`

func (q *Queries) TestFindAllUsers(ctx context.Context, db DBTX) ([]ShieldUser, error) {
	rows, err := db.Query(ctx, testFindAllUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ShieldUser
	for rows.Next() {
		var i ShieldUser
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Email,
			&i.IsEmailVerified,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const testFindUserByID = `-- name: TestFindUserByID :one
SELECT id, created_at, updated_at, email, is_email_verified FROM shield_users WHERE id = $1::UUID LIMIT 1
`

func (q *Queries) TestFindUserByID(ctx context.Context, db DBTX, id uuid.UUID) (ShieldUser, error) {
	row := db.QueryRow(ctx, testFindUserByID, id)
	var i ShieldUser
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.IsEmailVerified,
	)
	return i, err
}
