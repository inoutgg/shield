package shieldpassword

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"go.inout.gg/shield/internal/mocks"
)

func TestJoinPasswordChecker(t *testing.T) {
	t.Parallel()

	t.Run("it handles empty checkers list", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"

		// Arrange
		checker := JoinPasswordChecker()

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.NoError(t, actualErr)
	})

	t.Run("it should succeed", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"

		// Arrange
		ctrl := gomock.NewController(t)
		checker1 := mocks.NewMockPasswordChecker(ctrl)
		checker := JoinPasswordChecker(checker1)

		// Expected calls
		checker1.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil).Times(1)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.NoError(t, actualErr)
	})

	t.Run("it should fail", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"
		expectedErr := errors.New("weak password")

		// Arrange
		ctrl := gomock.NewController(t)
		checker1 := mocks.NewMockPasswordChecker(ctrl)
		checker := JoinPasswordChecker(checker1)

		// Expected calls
		checker1.EXPECT().Check(gomock.Any(), expectedPassword).Return(expectedErr).Times(1)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.ErrorIs(t, actualErr, expectedErr)
	})

	t.Run("multiple checkers all pass", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"

		// Arrange
		ctrl := gomock.NewController(t)
		checker1 := mocks.NewMockPasswordChecker(ctrl)
		checker2 := mocks.NewMockPasswordChecker(ctrl)
		checker3 := mocks.NewMockPasswordChecker(ctrl)
		checker := JoinPasswordChecker(checker1, checker2, checker3)

		// Expected calls
		checker1.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil).Times(1)
		checker2.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil).Times(1)
		checker3.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil).Times(1)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.NoError(t, actualErr)
	})

	t.Run("it should halt on first failure", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"
		expectedErr := errors.New("first checker failed")

		// Arrange
		ctrl := gomock.NewController(t)
		checker1 := mocks.NewMockPasswordChecker(ctrl)
		checker2 := mocks.NewMockPasswordChecker(ctrl)
		checker3 := mocks.NewMockPasswordChecker(ctrl)
		checker := JoinPasswordChecker(checker1, checker2, checker3)

		// Expected calls
		checker1.EXPECT().Check(gomock.Any(), expectedPassword).Return(expectedErr).Times(1)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.ErrorIs(t, actualErr, expectedErr)
	})

	t.Run("it should execute checkers until one fails", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"
		expectedErr := errors.New("last checker failed")

		// Arrange
		ctrl := gomock.NewController(t)
		checker1 := mocks.NewMockPasswordChecker(ctrl)
		checker2 := mocks.NewMockPasswordChecker(ctrl)
		checker3 := mocks.NewMockPasswordChecker(ctrl)
		checker := JoinPasswordChecker(checker1, checker2, checker3)

		// Expected calls
		checker1.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil).Times(1)
		checker2.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil).Times(1)
		checker3.EXPECT().Check(gomock.Any(), expectedPassword).Return(expectedErr).Times(1)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.ErrorIs(t, actualErr, expectedErr)
	})

	t.Run("should execute checkers in order", func(t *testing.T) {
		t.Parallel()

		expectedPassword := "password123"

		// Arrange
		ctrl := gomock.NewController(t)
		checker1 := mocks.NewMockPasswordChecker(ctrl)
		checker2 := mocks.NewMockPasswordChecker(ctrl)
		checker3 := mocks.NewMockPasswordChecker(ctrl)
		checker := JoinPasswordChecker(checker1, checker2, checker3)

		// Expected calls
		gomock.InOrder(
			checker1.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil),
			checker2.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil),
			checker3.EXPECT().Check(gomock.Any(), expectedPassword).Return(nil),
		)

		// Act
		actualErr := checker.Check(t.Context(), expectedPassword)

		// Assert
		assert.NoError(t, actualErr)
	})
}
