//nolint:goconst
package shieldpassword

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"go.inout.gg/shield/internal/mocks"
)

func TestPwndPasswordChecker_Check(t *testing.T) {
	t.Parallel()

	t.Run("it should succeed for safe password", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "unique-safe-password-12345"

		// Arrange
		ctrl := gomock.NewController(t)
		client := mocks.NewMockDoer(ctrl)
		server := mocks.NewPwnedPasswordsMockServer()
		checker := NewPwndPasswordChecker(func(c *PwndPasswordCheckerConfig) {
			c.Client = client
		})

		// Expected calls
		server.SetupMock(client)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.NoError(t, actualErr)
	})

	t.Run("it should fail for compromised password", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"

		// Arrange
		ctrl := gomock.NewController(t)
		client := mocks.NewMockDoer(ctrl)
		server := mocks.NewPwnedPasswordsMockServer().
			AddPassword("password123", 1000)
		checker := NewPwndPasswordChecker(func(c *PwndPasswordCheckerConfig) {
			c.Client = client
		})

		// Expected calls
		server.SetupMock(client)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.ErrorIs(t, actualErr, ErrPwnedPassword)
	})

	t.Run("it should fail on non-200 status code", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "anypassword"

		// Arrange
		ctrl := gomock.NewController(t)
		client := mocks.NewMockDoer(ctrl)
		server := mocks.NewPwnedPasswordsMockServer().
			WithStatusCode(http.StatusServiceUnavailable)
		checker := NewPwndPasswordChecker(func(c *PwndPasswordCheckerConfig) {
			c.Client = client
		})

		// Expected calls
		server.SetupMock(client)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		require.Error(t, actualErr)
		assert.Contains(t, actualErr.Error(), "unexpected status code")
	})

	t.Run("it should fail on network failure", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "anypassword"
		expectedErr := errors.New("network error")

		// Arrange
		ctrl := gomock.NewController(t)
		client := mocks.NewMockDoer(ctrl)
		server := mocks.NewPwnedPasswordsMockServer().
			WithError(expectedErr)
		checker := NewPwndPasswordChecker(func(c *PwndPasswordCheckerConfig) {
			c.Client = client
		})

		// Expected calls
		server.SetupMock(client)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		require.Error(t, actualErr)
		assert.Contains(t, actualErr.Error(), "failed to check password")
	})

	t.Run("it should handle password with zero count as safe", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "paddedpassword"

		// Arrange
		ctrl := gomock.NewController(t)
		client := mocks.NewMockDoer(ctrl)
		// Padded responses can have count of 0
		server := mocks.NewPwnedPasswordsMockServer().
			AddPassword("paddedpassword", 0)
		checker := NewPwndPasswordChecker(func(c *PwndPasswordCheckerConfig) {
			c.Client = client
		})

		// Expected calls
		server.SetupMock(client)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.NoError(t, actualErr)
	})

	t.Run("it should handle multiple passwords with same prefix", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"

		// Arrange
		ctrl := gomock.NewController(t)
		client := mocks.NewMockDoer(ctrl)
		server := mocks.NewPwnedPasswordsMockServer().
			AddPassword("password", 5000000).
			AddPassword("password1", 200000).
			AddPassword("password123", 100000)
		checker := NewPwndPasswordChecker(func(c *PwndPasswordCheckerConfig) {
			c.Client = client
		})

		// Expected calls
		server.SetupMock(client)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.ErrorIs(t, actualErr, ErrPwnedPassword)
	})
}
