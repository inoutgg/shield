package user

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"log/slog"

	"go.inout.gg/shield"
	"go.inout.gg/shield/strategy"
	"go.inout.gg/foundations/debug"
	httperror "go.inout.gg/foundations/http/error"
	"go.inout.gg/foundations/http/errorhandler"
	"go.inout.gg/foundations/http/htmx"
	"go.inout.gg/foundations/http/middleware"
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
	ErrorHandler errorhandler.ErrorHandler

	// Passthrough controls whether the request should be failed
	// on unauthorized access.
	Passthrough bool
}

func RedirectOnUnathenticatedUser(path string) errorhandler.ErrorHandler {
	return errorhandler.ErrorHandlerFunc(func(w http.ResponseWriter, r *http.Request, err error) {
		// User is not authenticated, let's redirect them to the provided page, while saving the
		// requested URL.
		if errors.Is(err, authentication.ErrUnauthorizedUser) {
			nu := url.URL{
				Path:     path,
				RawQuery: DefaultQueryNameRedirectURL + "=" + url.QueryEscape(r.RequestURI),
			}

			http.Redirect(w, r, nu.String(), http.StatusTemporaryRedirect)
			return
		}

		errorhandler.DefaultErrorHandler(w, r, err)
	})
}

// Middleware returns a middleware that authenticates the user and
// adds it to the request context.
//
// If the user is not authenticated, the error handler is called.
func Middleware[T any](
	authenticator strategy.Authenticator[T],
	config *Config,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		debug.Assert(config.ErrorHandler != nil, "shield/user: expected config.ErrorHandler to be defined")

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
func PreventAuthenticatedUserAccessMiddleware(redirectUrl string) middleware.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsAuthorized(r.Context()) {
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
func FromRequest[T any](r *http.Request) *strategy.Session[T] {
	return FromContext[T](r.Context())
}

// FromContext returns the user from the context if it exists.
//
// Make sure to use the Middleware before calling this function.
func FromContext[T any](ctx context.Context) *strategy.Session[T] {
	if user, ok := ctx.Value(kCtxKey).(*strategy.Session[T]); ok {
		return user
	}

	return nil
}

// IsAuthorized returns true if the user is authorized.
//
// It is a shortcut for FromContext(r.Context())!=nil.
func IsAuthorized(ctx context.Context) bool {
	return FromContext[any](ctx) != nil
}
