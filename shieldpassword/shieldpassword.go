// Package password implements a user registration and login flows with password.
package shieldpassword

import "go.inout.gg/foundations/debug"

// DefaultPasswordHasher is the default password hashing algorithm used across.
//
//nolint:gochecknoglobals
var DefaultPasswordHasher = NewBcryptPasswordHasher(BcryptDefaultCost)

//nolint:gochecknoglobals
var d = debug.Debuglog("shield/password")

// PasswordHasher is a hashing algorithm to hash password securely.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword string, password string) (bool, error)
}
