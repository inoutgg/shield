// uuidv7 is a wrapper around google's uuid package.
package tid

import (
	"fmt"

	"go.inout.gg/foundations/must"
	"go.jetify.com/typeid/v2"
)

type prefix string

var (
	PrefixUser          = prefix("user") //nolint:gochecknoglobals
	PrefixCredential    = prefix("cred") //nolint:gochecknoglobals
	PrefixSession       = prefix("sess") //nolint:gochecknoglobals
	PrefixRecoveryKey   = prefix("rk")   //nolint:gochecknoglobals
	PrefixPasswordReset = prefix("prk")  //nolint:gochecknoglobals
)

func MustUserID() typeid.TypeID          { return Must(PrefixUser) }
func MustCredentialID() typeid.TypeID    { return Must(PrefixCredential) }
func MustSessionID() typeid.TypeID       { return Must(PrefixSession) }
func MustRecoveryKeyID() typeid.TypeID   { return Must(PrefixRecoveryKey) }
func MustPasswordResetID() typeid.TypeID { return Must(PrefixPasswordReset) }

// Must returns a new random UUID. It panics if there is an error.
func Must(prefix prefix) typeid.TypeID {
	return must.Must(typeid.Generate(string(prefix)))
}

// FromString parses a UUID from a string.
func FromString(s string) (typeid.TypeID, error) {
	id, err := typeid.Parse(s)
	if err != nil {
		return id, fmt.Errorf(
			"shieldpassword: failed to parse UUID: %w",
			err,
		)
	}

	return id, nil
}
