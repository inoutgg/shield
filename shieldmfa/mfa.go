package shieldmfa

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/sliceutil"
)

var _ error = (*UserMFARequiredError)(nil)

var ErrNoMFAMethods = errors.New("no multi-factor authentication is enabled")

// UserMFARequiredError represents an error that occurs
// when a user is required to perform multi-factor authentication.
type UserMFARequiredError struct {
	mfas   []string
	userID int64
}

func NewUserMFARequiredError(userID int64, mfas []string) UserMFARequiredError {
	return UserMFARequiredError{
		userID: userID,
		mfas:   mfas,
	}
}

func (e UserMFARequiredError) Error() string {
	return fmt.Sprintf(
		"shieldmfa: user %d requires multi-factor authentication",
		e.userID,
	)
}

// UserID returns the user ID that requires multi-factor authentication.
func (e UserMFARequiredError) UserID() int64 {
	return e.userID
}

// AvailableMFAs returns the available multi-factor authentication methods
// for the user.
func (e UserMFARequiredError) AvailableMFAs() []string {
	return e.mfas
}

// IsUserMFARequiredError returns true if the error is a UserMFARequiredError.
func IsUserMFARequiredError(err error) bool {
	var t UserMFARequiredError
	return errors.As(err, &t)
}

// UserMFA returns a list of enabled MFAs for the user.
//
// If no MFAs are enabled a ErrNoMFAs is returned.
func UserMFA(ctx context.Context, dbtx dbsqlc.DBTX, userID int64) ([]string, error) {
	mfas, err := dbsqlc.New().GetUserMFAs(ctx, dbtx, userID)
	if err != nil {
		return nil, fmt.Errorf("shieldmfa: failed to get user MFAs: %w", err)
	}

	if errors.Is(err, pgx.ErrNoRows) || len(mfas) == 0 {
		return nil, ErrNoMFAMethods
	}

	return sliceutil.Map(mfas, func(mfa dbsqlc.ShieldUserMfa) string {
		return mfa.Name
	}), nil
}
