package shielduser

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/htmx"
	"go.inout.gg/foundations/http/httperror"
	"go.inout.gg/foundations/http/httpmiddleware"
	"go.inout.gg/shield"
	"go.inout.gg/shield/shieldstrategy"
)

type ctxKey struct{}

var kCtxKey = ctxKey{}

const (
	DefaultQueryNameRedirectURL = "redirect_url"
)

// Config is the configuration for the middleware.
type Config struct {
	Logger *slog.Logger

	// ErrorHandler is the error handler that is called when the user is not
	// authenticated.
	// If nil, the default error handler is used.
	ErrorHandler httperror.ErrorHandler

	// Passthrough controls whether the request should be failed
	// on unauthorized access.
	Passthrough bool
}

func RedirectOnUnathenticatedUser(path string) httperror.ErrorHandler {
	return httperror.ErrorHandlerFunc(func(w http.ResponseWriter, r *http.Request, err error) {
		// User is not authenticated, let's redirect them to the provided page, while saving the
		// requested URL.
		if errors.Is(err, shield.ErrUnauthenticatedUser) {
			nu := url.URL{
				Path:     path,
				RawQuery: DefaultQueryNameRedirectURL + "=" + url.QueryEscape(r.RequestURI),
			}

			http.Redirect(w, r, nu.String(), http.StatusTemporaryRedirect)
			return
		}

		httperror.DefaultErrorHandler(w, r, err)
	})
}

// Middleware returns a middleware that authenticates the user and
// adds it to the request context.
//
// If the user is not authenticated, the error handler is called.
func Middleware[T any](
	authenticator shieldstrategy.Authenticator[T],
	config *Config,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		debug.Assert(config.ErrorHandler != nil, "expected config.ErrorHandler to be defined")

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := authenticator.Authenticate(w, r)
			if err != nil {
				// If Passthrough is set ignore the error and continue.
				if !config.Passthrough {
					config.ErrorHandler.ServeHTTP(
						w,
						r,
						httperror.FromError(err, http.StatusUnauthorized, "unauthorized access"),
					)

					return
				}
			}

			newCtx := context.WithValue(r.Context(), kCtxKey, user)
			next.ServeHTTP(
				w,
				r.WithContext(newCtx),
			)
		})
	}
}

// PreventAuthenticatedUserAccessMiddleware is a middleware that redirects the user to the
// provided URL if the user is authenticated.
//
// Make sure to use the Middleware before adding this one.
func PreventAuthenticatedUserAccessMiddleware(redirectUrl string) httpmiddleware.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsAuthenticated(r.Context()) {
				htmx.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// FromRequest returns the user from the request context if it exists.
//
// Make sure to use the Middleware before calling this function.
func FromRequest[T any](r *http.Request) *shieldstrategy.Session[T] {
	return FromContext[T](r.Context())
}

// FromContext returns the user from the context if it exists.
//
// Make sure to use the Middleware before calling this function.
func FromContext[T any](ctx context.Context) *shieldstrategy.Session[T] {
	if user, ok := ctx.Value(kCtxKey).(*shieldstrategy.Session[T]); ok {
		return user
	}

	return nil
}

// IsAuthenticated returns true if the user is authorized.
//
// It is a shortcut for FromContext(r.Context())!=nil.
func IsAuthenticated(ctx context.Context) bool {
	return FromContext[any](ctx) != nil
}
