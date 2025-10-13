package shielduser

import (
	"context"
	"fmt"

	"go.inout.gg/foundations/dbsql"
	"go.jetify.com/typeid/v2"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
)

type User[T any] struct {
	T               *T
	Email           string
	ID              typeid.TypeID
	IsEmailVerified bool
}

// UserByID retrieves a user by their ID.
func UserByID(ctx context.Context, dbtx dbsqlc.DBTX, id typeid.TypeID) (User[any], error) {
	var user User[any]

	dbUser, err := dbsqlc.New().FindUserByID(ctx, dbtx, id)
	if err != nil {
		if dbsql.IsNotFoundError(err) {
			return user, shield.ErrUserNotFound
		}

		return user, fmt.Errorf("shielduser: failed to find user by id: %w", err)
	}

	user.ID = dbUser.ID
	user.Email = dbUser.Email
	user.IsEmailVerified = dbUser.IsEmailVerified

	return user, nil
}

// UserByEmail retrieves a user by their email.
func UserByEmail(ctx context.Context, dbtx dbsqlc.DBTX, email string) (User[any], error) {
	var user User[any]

	dbUser, err := dbsqlc.New().FindUserByEmail(ctx, dbtx, email)
	if err != nil {
		if dbsql.IsNotFoundError(err) {
			return user, shield.ErrUserNotFound
		}

		return user, fmt.Errorf("shielduser: failed to find user by email: %w", err)
	}

	user.ID = dbUser.ID
	user.Email = dbUser.Email
	user.IsEmailVerified = dbUser.IsEmailVerified

	return user, nil
}
