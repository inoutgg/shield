// Package shieldpassword implements a user registration and login flows with password.
package shieldpassword

import (
	"context"

	"go.inout.gg/foundations/debug"
)

var _ PasswordChecker = (*passwordChecker)(nil)

// DefaultPasswordHasher is the default password hashing algorithm used across.
//
//nolint:gochecknoglobals
var DefaultPasswordHasher = NewBcryptPasswordHasher(BcryptDefaultCost)

//nolint:gochecknoglobals
var d = debug.Debuglog("shieldpassword")

// PasswordHasher is a hashing algorithm to hash password securely.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword string, password string) (bool, error)
}

// PasswordChecker checks if the password passes the verification checks.
//
// See PwndPasswordVerifier, PasswordStrengthVerifier for concrete
// implementations.
type PasswordChecker interface {
	// Checker checks if the password passes the verification checks.
	Check(context.Context, string) error
}

func JoinPasswordChecker(checkers ...PasswordChecker) PasswordChecker {
	return &passwordChecker{checkers: checkers}
}

type passwordChecker struct {
	checkers []PasswordChecker
}

func (p *passwordChecker) Check(ctx context.Context, password string) error {
	for _, checker := range p.checkers {
		if err := checker.Check(ctx, password); err != nil {
			//nolint:wrapcheck // no need to wrap error here, since passwordCheckers
			// is just a wrapper.
			return err
		}
	}

	return nil
}
