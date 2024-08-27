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
	ErrAuthorizedUser   = errors.New("shield: authorized user access")
	ErrUnauthorizedUser = errors.New("shield: unauthorized user access")
	ErrUserNotFound     = errors.New("shield: user not found")
)

type User[T any] struct {
	// ID is the user ID.
	ID uuid.UUID

	// T holds additional data.
	//
	// Make sure that the data is JSON-serializable.
	T *T
}
