package shieldpassword

import "context"

var _ PasswordChecker = (*combinedPasswordChecker)(nil)

// PasswordChecker checks if the password passes the verification checks.
//
// See PwndPasswordChecker, PasswordStrengthChecker for concrete
// implementations.
//
//go:generate mockgen -destination=../internal/mocks/password_checker_mock.go -package=mocks . PasswordChecker
type PasswordChecker interface {
	// Checker checks if the password passes the verification checks.
	Check(context.Context, string) error
}

// JoinPasswordChecker creates a new PasswordChecker that combines multiple
// PasswordCheckers and executes them sequentially.
//
// The returned PasswordChecker will return the first error encountered.
func JoinPasswordChecker(checkers ...PasswordChecker) PasswordChecker {
	return &combinedPasswordChecker{checkers: checkers}
}

// combinedPasswordChecker combines multiple PasswordCheckers
// and executes them sequentially.
type combinedPasswordChecker struct {
	checkers []PasswordChecker
}

func (p *combinedPasswordChecker) Check(ctx context.Context, password string) error {
	for _, checker := range p.checkers {
		if err := checker.Check(ctx, password); err != nil {
			//nolint:wrapcheck // no need to wrap error here, since passwordCheckers
			// is just a wrapper.
			return err
		}
	}

	return nil
}
