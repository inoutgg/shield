package shield

import (
	"errors"

	"github.com/google/uuid"
)

const (
	CredentialPassword   = "password"
	CredentialPasskey    = "passkey"
	CredentialSsoTwitter = "sso_twitter"
	CredentialSsoGoogle  = "sso_google"
)

var (
	ErrAuthenticatedUser   = errors.New("shield: authenticated user access")
	ErrUnauthenticatedUser = errors.New("shield: unauthenticated user access")
	ErrUserNotFound        = errors.New("shield: user not found")
)

type User[T any] struct {
	// ID is the user ID.
	ID uuid.UUID

	// T holds additional data.
	//
	// Make sure that the data is JSON-serializable.
	T *T
}
