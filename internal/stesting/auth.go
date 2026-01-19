package stesting

import (
	"context"
	"testing"
)

func AuthContext(t *testing.T) context.Context {
	t.Helper()

	// TODO: Implement authentication context for testing
	return t.Context()
}
