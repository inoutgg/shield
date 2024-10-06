package shieldpasswordverifier

import (
	"strings"
)

var (
	_ PasswordVerifier = (*passwordVerifier)(nil)
	_ error            = (*PasswordVerificationError)(nil)
)

type Reason string

const (
	ReasonPasswordToShort      Reason = "Password is too short"
	ReasonMissingRequiredChars Reason = "Password is missing required characters"
)

type PasswordVerificationError struct {
	message string
	Reasons []Reason
}

func (e *PasswordVerificationError) Error() string {
	return e.message
}

type Config struct {
	// MinLength is the minimum length of the password.
	MinLength int

	// RequiredChars is the list of required characters.
	RequiredChars PasswordRequiredChars
}

// NewConfig creates a new Config with defaults.
//
// cfgs modifiers can be used to optionally override the defaults.
func NewConfig(cfgs ...func(*Config)) *Config {
	config := &Config{}
	for _, f := range cfgs {
		f(config)
	}

	config.defaults()

	return config
}

// defaults set c config fields to default values.
//
// defaults might panic if the defaultRequiredChars list is invalid.
func (c *Config) defaults() {
	if c.RequiredChars == nil {
		c.RequiredChars = DefaultPasswordRequiredChars
	}

	if c.MinLength == 0 {
		c.MinLength = 8
	}
}

// PasswordVerifier verifies strongness of the password.
type PasswordVerifier interface {
	Verify(password string) error
}

type passwordVerifier struct {
	config *Config
}

// New creates a new PasswordVerifier.
func New(config *Config) (*passwordVerifier, error) {
	return &passwordVerifier{
		config,
	}, nil
}

// Verify verifies the strongness password.
func (v *passwordVerifier) Verify(password string) error {
	var reasons []Reason
	var messages []string

	if len(password) < v.config.MinLength {
		reasons = append(reasons, ReasonPasswordToShort)
	}

	for _, requiredCharsPart := range v.config.RequiredChars {
		if !strings.ContainsAny(password, requiredCharsPart) {
			reasons = append(reasons, ReasonMissingRequiredChars)
		}

		if len(reasons) > 0 {
			return &PasswordVerificationError{
				message: strings.Join(messages, ", "),
				Reasons: reasons,
			}
		}
	}

	return nil
}
