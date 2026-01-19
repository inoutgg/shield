package shieldpassword

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/must"

	"go.inout.gg/shield/internal/sliceutil"
)

var _ PasswordChecker = (*PasswordStrengthChecker)(nil)

var ErrPasswordTooShort = errors.New("shieldpassword: password is too short")

// PasswordRuleViolationError is returned when a password doesn't meet pattern requirements.
type PasswordRuleViolationError struct {
	Pattern  string
	MinCount int
}

func (e PasswordRuleViolationError) Error() string {
	return fmt.Sprintf(
		"shieldpassword: password requires at least %d of %q",
		e.MinCount,
		e.Pattern,
	)
}

// DefaultPasswordRules implements a password policy with the following requirements:
//   - Minimum 12 characters
//   - At least 2 lowercase letters
//   - At least 2 uppercase letters
//   - At least 2 digits
//   - At least 1 special character
var DefaultPasswordRules PasswordRules //nolint:gochecknoglobals

//nolint:gochecknoinits
func init() {
	must.Must1(DefaultPasswordRules.Parse(
		"2@abcdefghijklmnopqrstuvwxyz::" + // at least 2 lowercase
			"2@ABCDEFGHIJKLMNOPQRSTUVWXYZ::" + // at least 2 uppercase
			"2@0123456789::" + // at least 2 digits
			"1@!@#$%^&*()-_=+[]{}|;:,.<>?/~`", // at least 1 special character
	))
}

// PasswordRule defines a character set and the minimum number of characters
// from that set required in a password.
type PasswordRule struct {
	Pattern  string
	MinCount int
}

// Check verifies if the password meets this pattern requirement.
// Returns ErrMissingRequiredChars if the requirement is not met.
func (p *PasswordRule) Check(password string) error {
	count := p.countMatches(password)
	if count < p.MinCount {
		return &PasswordRuleViolationError{
			Pattern:  p.Pattern,
			MinCount: p.MinCount,
		}
	}

	return nil
}

// countMatches counts how many characters in password are present in the pattern.
func (p *PasswordRule) countMatches(password string) int {
	count := 0

	for _, ch := range password {
		if strings.ContainsRune(p.Pattern, ch) {
			count++
		}
	}

	return count
}

// PasswordRules represents a list of required patterns in the password.
type PasswordRules []PasswordRule

// Parse parses a string representation of password patterns into a PasswordRules.
// Format: <count-1>@<charset-1>::<count-2>@<charset-2>::...::<count-n>@<charset-n>
//
// Examples:
//   - "2@abc" -> charset="abc", count=2
//   - "1@0123456789" -> charset="0123456789", count=1
//   - "2@abcdefghijklmnopqrstuvwxyz::1@ABCDEFGHIJKLMNOPQRSTUVWXYZ::1@0123456789"
//     requires at least 2 lowercase, 1 uppercase, and 1 digit
//   - "2@!@#$%^&*():" -> charset="!@#$%^&*():", count=2
func (s *PasswordRules) Parse(source string) error {
	parts := sliceutil.Filter(
		strings.Split(source, "::"),
		func(s string) bool { return len(s) > 0 },
	)

	rules := make([]PasswordRule, 0, len(parts))

	for _, part := range parts {
		countStr, pattern, ok := strings.Cut(part, "@")
		if !ok {
			return fmt.Errorf(
				"shieldpassword: missing @ separator in pattern %q: format must be <count>@<charset>",
				part,
			)
		}

		if countStr == "" {
			return fmt.Errorf(
				"shieldpassword: missing count before @ in pattern %q",
				part,
			)
		}

		if pattern == "" {
			return fmt.Errorf(
				"shieldpassword: empty charset after @ in pattern %q",
				part,
			)
		}

		count, err := strconv.Atoi(countStr)
		if err != nil {
			return fmt.Errorf(
				"shieldpassword: invalid count in pattern %q: %w",
				part,
				err,
			)
		}

		if count < 1 {
			return fmt.Errorf(
				"shieldpassword: min count must be at least 1 in pattern %q",
				part,
			)
		}

		rules = append(rules, PasswordRule{
			Pattern:  pattern,
			MinCount: count,
		})
	}

	*s = rules

	return nil
}

func WithPasswordRules(rules PasswordRules) func(*PasswordStrengthCheckerConfig) {
	return func(c *PasswordStrengthCheckerConfig) { c.Rules = rules }
}

func WithMinLength(minLength int) func(*PasswordStrengthCheckerConfig) {
	return func(c *PasswordStrengthCheckerConfig) { c.MinLength = minLength }
}

type PasswordStrengthCheckerConfig struct {
	Rules     PasswordRules
	MinLength int
}

func (c *PasswordStrengthCheckerConfig) defaults() {
	if c.Rules == nil {
		c.Rules = DefaultPasswordRules
	}

	c.MinLength = max(c.MinLength, 12)

	debug.Assert(c.Rules != nil, "RequiredChars must be set")
	debug.Assert(c.MinLength >= 12, "MinLength must be at least 12")
}

// PasswordStrengthChecker verifies strength of the password.
type PasswordStrengthChecker struct {
	config *PasswordStrengthCheckerConfig
}

// NewPasswordStrengthChecker creates a new password strength verifier with default configuration.
func NewPasswordStrengthChecker(
	opts ...func(*PasswordStrengthCheckerConfig),
) *PasswordStrengthChecker {
	var config PasswordStrengthCheckerConfig
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	return &PasswordStrengthChecker{config: &config}
}

func (c *PasswordStrengthChecker) Check(_ context.Context, password string) error {
	var errs []error

	if len(password) < c.config.MinLength {
		errs = append(errs, ErrPasswordTooShort)
	}

	for _, rule := range c.config.Rules {
		if err := rule.Check(password); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
