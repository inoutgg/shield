package shieldpassword

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/unicode/norm"
)

var _ PasswordHasher = (*bcryptPasswordHasher)(nil)

const (
	BcryptDefaultCost = bcrypt.DefaultCost
)

// DefaultPasswordHasher is the default password hashing algorithm used across.
//
//nolint:gochecknoglobals
var DefaultPasswordHasher = NewBcryptPasswordHasher(BcryptDefaultCost)

// PasswordHasher is a hashing algorithm to hash password securely.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword string, password string) (bool, error)
}

type bcryptPasswordHasher struct {
	cost int
}

// NewBcryptPasswordHasher creates a password hasher using the bcrypt algorithm.
//
// Security: Please note that bcrypt has a maximum input length of 72 bytes.
// For passwords requiring more than 72 bytes of data, consider using an alternative
// algorithm such as Argon2.
func NewBcryptPasswordHasher(cost int) PasswordHasher {
	return &bcryptPasswordHasher{cost}
}

func (h *bcryptPasswordHasher) Hash(password string) (string, error) {
	passwordBytes := []byte(norm.NFKC.String(password))

	hash, err := bcrypt.GenerateFromPassword(passwordBytes, h.cost)
	if err != nil {
		return "", fmt.Errorf(
			"shieldpassword: unable to generate a bcrypt hash: %w",
			err,
		)
	}

	return string(hash), nil
}

func (h *bcryptPasswordHasher) Verify(
	hashedPassword string,
	password string,
) (bool, error) {
	passwordBytes := []byte(norm.NFKC.String(password))
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), passwordBytes); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}

		return false, fmt.Errorf(
			"shieldpassword: failed while comparing passwords: %w",
			err,
		)
	}

	return true, nil
}
