// Package password implements a user registration and login flows with password.
package password

import "go.inout.gg/foundations/debug"

// PasswordHasher is a hashing algorithm to hash password securely.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword string, password string) (bool, error)
}

var (
	// DefaultPasswordHasher is the default password hashing algorithm used across.
	DefaultPasswordHasher = NewBcryptPasswordHasher(BcryptDefaultCost)
)

var d = debug.Debuglog("shield/password")
