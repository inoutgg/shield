package shielduser_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.inout.gg/foundations/http/httphandler"
	"go.uber.org/mock/gomock"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/mocks"
	"go.inout.gg/shield/shielduser"
)

func TestMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("unauthenticated request does not inject session", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		authenticator := mocks.NewMockAuthenticator[any, any](ctrl)
		authenticator.EXPECT().
			Authenticate(gomock.Any(), gomock.Any()).
			Return(nil, shield.ErrUnauthenticatedUser)

		var (
			gotSession       *shielduser.Session[any]
			gotErr           error
			gotAuthenticated bool
		)

		h := shielduser.Middleware[any, any](
			authenticator,
			httphandler.ErrorHandlerFunc(func(w http.ResponseWriter, _ *http.Request, err error) {
				t.Fatalf("unexpected middleware error: %v", err)
			}),
		)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSession, gotErr = shielduser.FromRequest[any](r)
			gotAuthenticated = shielduser.IsAuthenticated[any](r.Context())
			w.WriteHeader(http.StatusNoContent)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		assert.Equal(t, http.StatusNoContent, res.Code)
		assert.Nil(t, gotSession)
		assert.ErrorIs(t, gotErr, shield.ErrUnauthenticatedUser)
		assert.False(t, gotAuthenticated)
	})

	t.Run("mfa required request injects partial session", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		authenticator := mocks.NewMockAuthenticator[any, any](ctrl)

		expected := &shielduser.Session[any]{
			ID:            12,
			UserID:        34,
			IsMFARequired: true,
		}

		authenticator.EXPECT().
			Authenticate(gomock.Any(), gomock.Any()).
			Return(expected, shield.ErrMFARequired)

		var (
			gotSession       *shielduser.Session[any]
			gotErr           error
			gotAuthenticated bool
		)

		h := shielduser.Middleware[any, any](
			authenticator,
			httphandler.ErrorHandlerFunc(func(w http.ResponseWriter, _ *http.Request, err error) {
				t.Fatalf("unexpected middleware error: %v", err)
			}),
		)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSession, gotErr = shielduser.FromRequest[any](r)
			gotAuthenticated = shielduser.IsAuthenticated[any](r.Context())
			w.WriteHeader(http.StatusNoContent)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		assert.Equal(t, http.StatusNoContent, res.Code)
		assert.NotNil(t, gotSession)
		assert.Equal(t, expected.ID, gotSession.ID)
		assert.Equal(t, expected.UserID, gotSession.UserID)
		assert.True(t, gotSession.IsMFARequired)
		assert.ErrorIs(t, gotErr, shield.ErrMFARequired)
		assert.False(t, gotAuthenticated)
	})

	t.Run("authenticated request injects full session", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		authenticator := mocks.NewMockAuthenticator[any, any](ctrl)

		expected := &shielduser.Session[any]{
			ID:     56,
			UserID: 78,
		}

		authenticator.EXPECT().
			Authenticate(gomock.Any(), gomock.Any()).
			Return(expected, nil)

		var (
			gotSession       *shielduser.Session[any]
			gotErr           error
			gotAuthenticated bool
		)

		h := shielduser.Middleware[any, any](
			authenticator,
			httphandler.ErrorHandlerFunc(func(w http.ResponseWriter, _ *http.Request, err error) {
				t.Fatalf("unexpected middleware error: %v", err)
			}),
		)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSession, gotErr = shielduser.FromRequest[any](r)
			gotAuthenticated = shielduser.IsAuthenticated[any](r.Context())
			w.WriteHeader(http.StatusNoContent)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		assert.Equal(t, http.StatusNoContent, res.Code)
		assert.NotNil(t, gotSession)
		assert.Equal(t, expected.ID, gotSession.ID)
		assert.Equal(t, expected.UserID, gotSession.UserID)
		assert.NoError(t, gotErr)
		assert.True(t, gotAuthenticated)
	})
}
