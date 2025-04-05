package shieldpasswordverifier

import (
	"strings"

	"go.inout.gg/foundations/must"

	"go.inout.gg/shield/internal/sliceutil"
)

//nolint:gochecknoglobals
var DefaultPasswordRequiredChars PasswordRequiredChars

//nolint:gochecknoinits
func init() {
	must.Must1(DefaultPasswordRequiredChars.Parse(""))
}

// PasswordRequiredChars represents a list of characters that are mandatory to be presented in the password.
type PasswordRequiredChars []string

func (s *PasswordRequiredChars) Parse(source string) error {
	parts := sliceutil.Filter(
		strings.Split(source, "::"),
		func(s string) bool { return len(s) > 0 },
	)

	*s = PasswordRequiredChars(parts)

	return nil
}
