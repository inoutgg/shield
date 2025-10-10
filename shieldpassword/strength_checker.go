package shieldpassword

import (
	"context"
	"errors"
	"strings"

	"go.inout.gg/foundations/debug"
)

var _ PasswordChecker = (*passwordStrengthChecker)(nil)

var (
	ErrPasswordToShort      = errors.New("shieldpassword: password is too short")
	ErrMissingRequiredChars = errors.New(
		"shieldpassword: password is missing required characters",
	)
)

func WithRequiredChars(requiredChars PasswordRequiredChars) func(*PasswordStrengthCheckerConfig) {
	return func(c *PasswordStrengthCheckerConfig) { c.RequiredChars = requiredChars }
}

func WithMinLength(minLength int) func(*PasswordStrengthCheckerConfig) {
	return func(c *PasswordStrengthCheckerConfig) { c.MinLength = minLength }
}

type PasswordStrengthCheckerConfig struct {
	RequiredChars PasswordRequiredChars
	MinLength     int
}

func (c *PasswordStrengthCheckerConfig) defaults() {
	if c.RequiredChars == nil {
		c.RequiredChars = DefaultPasswordRequiredChars
	}

	c.MinLength = max(c.MinLength, 12)

	debug.Assert(c.RequiredChars != nil, "RequiredChars must be set")
	debug.Assert(c.MinLength >= 12, "MinLength must be at least 12")
}

// PasswordStrengthVerifier verifies strength of the password.
type passwordStrengthChecker struct {
	config *PasswordStrengthCheckerConfig
}

// NewPasswordStrengthChecker creates a new password strength verifier.
func NewPasswordStrengthChecker(opts ...func(*PasswordStrengthCheckerConfig)) PasswordChecker {
	var config PasswordStrengthCheckerConfig
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	return &passwordStrengthChecker{config: &config}
}

func (v *passwordStrengthChecker) Check(_ context.Context, password string) error {
	var errs []error

	if len(password) < v.config.MinLength {
		errs = append(errs, ErrPasswordToShort)
	}

	for _, requiredCharsPart := range v.config.RequiredChars {
		if !strings.ContainsAny(password, requiredCharsPart) {
			errs = append(errs, ErrMissingRequiredChars)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
