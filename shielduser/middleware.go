package shielduser

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httperror"
	"go.inout.gg/foundations/http/httphandler"
	"go.inout.gg/foundations/http/httpmiddleware"

	"go.inout.gg/shield"
)

type ctxKey struct{}

var kCtxKey = ctxKey{} //nolint:gochecknoglobals

var d = debug.Debuglog("shielduser") //nolint:gochecknoglobals

// Config is the configuration for the middleware.
type Config struct {
	Logger *slog.Logger
}

func (c *Config) defaults() {
}

// Middleware returns a middleware that authenticates a user and adds
// the session to the context on successful authentication.
//
// If user is not authenticated, the middleware passes the request without
// session context. To prevent unauthorized access, use RequireAuthMiddleware
//
// If the authentication fails due to authenticator failure errorHandler is called
// with the error.
func Middleware[U, S any](
	authenticator Authenticator[U, S],
	errorHandler httphandler.ErrorHandler,
	opts ...func(*Config),
) httpmiddleware.MiddlewareFunc {
	debug.Assert(authenticator != nil, "authenticator must be set")
	debug.Assert(errorHandler != nil, "errorHandler must be set")

	var config Config
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				sess, err := authenticator.Authenticate(w, r)
				if err != nil &&
					!errors.Is(err, shield.ErrUnauthenticatedUser) &&
					!errors.Is(err, shield.ErrMFARequired) {
					errorHandler.ServeHTTP(
						w,
						r,
						httperror.FromError(
							err,
							http.StatusInternalServerError,
							"unknown error",
						),
					)

					return
				}

				if errors.Is(err, shield.ErrUnauthenticatedUser) {
					next.ServeHTTP(w, r)

					return
				}

				next.ServeHTTP(
					w,
					r.WithContext(
						context.WithValue(r.Context(), kCtxKey, sess),
					),
				)
			},
		)
	}
}

// RequireAuthenticatedUserMiddleware redirects a user to the
// provided URL if the user is not authenticated.
//
// Make sure to use the Middleware before adding this one.
func RequireAuthenticatedUserMiddleware[S any](redirectURL string) httpmiddleware.MiddlewareFunc {
	return redirectMiddleware[S](redirectURL, true)
}

// PreventAuthenticatedUserMiddleware redirects a user to the
// provided URL if the user is authenticated.
//
// Make sure to use the Middleware before adding this middleware.
func PreventAuthenticatedUserMiddleware[S any](redirectURL string) httpmiddleware.MiddlewareFunc {
	return redirectMiddleware[S](redirectURL, false)
}

// redirectMiddleware is the shared implementation for RequireAuthenticatedUserMiddleware
// and PreventAuthenticatedUserMiddleware.
//
// When requireAuth is true, it redirects unauthenticated users.
// When requireAuth is false, it redirects authenticated users.
func redirectMiddleware[S any](redirectURL string, requireAuth bool) httpmiddleware.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authenticated := IsAuthenticated[S](r.Context())

			if requireAuth && !authenticated {
				d("user is not authenticated")
				http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)

				return
			}

			if !requireAuth && authenticated {
				d("redirecting authenticated user")
				http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// FromRequest returns the user from the request context if it exists.
//
// Make sure to use the Middleware before calling this function.
func FromRequest[S any](r *http.Request) (*Session[S], error) {
	return FromContext[S](r.Context())
}

// FromContext returns the user from the context if it exists.
//
// If MFA is required for the session, both session and
// shield.ErrMFARequired are returned.
//
// Make sure to use the Middleware before calling this function.
func FromContext[S any](ctx context.Context) (*Session[S], error) {
	sess, ok := ctx.Value(kCtxKey).(*Session[S])
	if ok && sess != nil {
		if sess.IsMFARequired {
			return sess, shield.ErrMFARequired
		}

		return sess, nil
	}

	return nil, shield.ErrUnauthenticatedUser
}

// IsAuthenticated returns true if the user is authorized.
func IsAuthenticated[S any](ctx context.Context) bool {
	_, err := FromContext[S](ctx)
	return err == nil
}
