package shield

import (
	"errors"
	"log/slog"
	"os"

	"github.com/go-playground/mold/v4/modifiers"
	"github.com/go-playground/mold/v4/scrubbers"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

const (
	CredentialPassword   = "password"
	CredentialPasskey    = "passkey"
	CredentialSsoTwitter = "sso_twitter"
	CredentialSsoGoogle  = "sso_google"
)

var (
	DefaultFormValidator = validator.New(validator.WithRequiredStructEnabled()) //nolint:gochecknoglobals
	DefaultFormScrubber  = scrubbers.New()                                      //nolint:gochecknoglobals
	DefaultFormModifier  = modifiers.New()                                      //nolint:gochecknoglobals
)

var (
	ErrAuthenticatedUser   = errors.New("shield: authenticated user access")
	ErrUnauthenticatedUser = errors.New("shield: unauthenticated user access")
	ErrUserNotFound        = errors.New("shield: user not found")
)

//nolint:gochecknoglobals
var DefaultLogger = slog.New(slog.NewTextHandler(os.Stdout, nil))

type User[T any] struct {
	T  *T
	ID uuid.UUID
}
