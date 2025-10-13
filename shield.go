package shield

import (
	"errors"
	"log/slog"
	"os"

	"github.com/go-playground/mold/v4/modifiers"
	"github.com/go-playground/mold/v4/scrubbers"
	"github.com/go-playground/validator/v10"
)

const (
	CredentialPassword   = "password"
	CredentialPasskey    = "passkey"
	CredentialSsoTwitter = "sso_twitter"
	CredentialSsoGoogle  = "sso_google"
)

const (
	MFAPasskey = "mfa_passkey"
	MFAEmail   = "mfa_email"
	MFAOTP     = "mfa_otp"
)

var (
	//nolint:gochecknoglobals
	DefaultFormValidator = validator.New(
		validator.WithRequiredStructEnabled(),
	)
	DefaultFormScrubber = scrubbers.New() //nolint:gochecknoglobals
	DefaultFormModifier = modifiers.New() //nolint:gochecknoglobals
)

var (
	ErrAuthenticatedUser   = errors.New("shield: authenticated user access")
	ErrMFARequired         = errors.New("shield: mfa required")
	ErrUnauthenticatedUser = errors.New(
		"shield: unauthenticated user access",
	)
	ErrUserNotFound = errors.New("shield: user not found")
)

//nolint:gochecknoglobals
var DefaultLogger = slog.New(slog.NewTextHandler(os.Stdout, nil))
