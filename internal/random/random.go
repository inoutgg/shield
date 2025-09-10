package random

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// secureBytes returns a securely random byte slice of length l.
func secureBytes(l int) ([]byte, error) {
	bytes := make([]byte, l)

	_, err := rand.Read(bytes)
	if err != nil {
		return bytes, fmt.Errorf(
			"shield: error reading random bytes: %w",
			err,
		)
	}

	return bytes, nil
}

// SecureHexString returns a securely random hex string of length 2*l.
func SecureHexString(l int) (string, error) {
	bytes, err := secureBytes(l)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
