package shield

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/go-playground/mold/v4/modifiers"
	"github.com/go-playground/mold/v4/scrubbers"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/sliceutil"
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

type User[T any] struct {
	T          *T
	cachedMfas []string
	ID         uuid.UUID
}

// MFA returns a list of enabled MFAs for the user.
//
// If no MFAs are enabled, an empty slice is returned.
func (u *User[_]) MFA(ctx context.Context, conn dbsqlc.DBTX) ([]string, error) {
	if len(u.cachedMfas) > 0 {
		return u.cachedMfas, nil
	}

	mfas, err := dbsqlc.New().GetUserMFAs(ctx, conn, u.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
	}

	u.cachedMfas = sliceutil.Map(
		mfas,
		func(mfa dbsqlc.ShieldUserMfa) string {
			return mfa.Name
		},
	)

	return u.cachedMfas, nil
}
