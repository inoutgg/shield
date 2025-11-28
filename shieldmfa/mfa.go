package shieldmfa

import (
	"context"
	"errors"
	"fmt"

	"go.jetify.com/typeid/v2"

	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/sliceutil"
)

var ErrNoMFAMethods = errors.New("no multi-factor authentication is enabled")

var _ error = UserMFARequiredError{} //nolint:exhaustruct

// UserMFARequiredError represents an error that occurs
// when a user is required to perform multi-factor authentication.
type UserMFARequiredError struct {
	userID typeid.TypeID
	mfas   []string
}

func NewUserMFARequiredError(userID typeid.TypeID, mfas []string) UserMFARequiredError {
	return UserMFARequiredError{
		userID: userID,
		mfas:   mfas,
	}
}

func (e UserMFARequiredError) Error() string {
	return fmt.Sprintf(
		"shieldmfa: user %s requires multi-factor authentication",
		e.userID.String(),
	)
}

// UserID returns the user ID that requires multi-factor authentication.
func (e UserMFARequiredError) UserID() typeid.TypeID {
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
func UserMFA(ctx context.Context, dbtx dbsqlc.DBTX, userID typeid.TypeID) ([]string, error) {
	mfas, err := dbsqlc.New().GetUserMFAs(ctx, dbtx, userID)
	if err != nil {
		return nil, fmt.Errorf("shieldmfa: failed to get user MFAs: %w", err)
	}

	if len(mfas) == 0 {
		return nil, ErrNoMFAMethods
	}

	return sliceutil.Map(mfas, func(mfa dbsqlc.ShieldUserMfa) string {
		return mfa.Name
	}), nil
}
