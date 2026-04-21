package shieldunionsession

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/mocks"
	"go.inout.gg/shield/shielduser"
)

func TestNew_MFARequiredShortCircuits(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	first := mocks.NewMockAuthenticator[any, any](ctrl)
	second := mocks.NewMockAuthenticator[any, any](ctrl)

	expected := &shielduser.Session[any]{
		ID:            1,
		UserID:        2,
		IsMFARequired: true,
	}

	first.EXPECT().
		Authenticate(gomock.Any(), gomock.Any()).
		Return(expected, shield.ErrMFARequired)

	authenticator := New[any, any](
		first,
		second,
	)

	sess, err := authenticator.Authenticate(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	assert.ErrorIs(t, err, shield.ErrMFARequired)
	assert.Equal(t, expected, sess)
	assert.True(t, sess.IsMFARequired)
}
