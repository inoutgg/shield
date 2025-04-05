package shielduser

import (
	"context"
	"log/slog"
	"net/http"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httperror"
	"go.inout.gg/foundations/http/httpmiddleware"

	"go.inout.gg/shield"
	"go.inout.gg/shield/shieldstrategy"
)

type ctxKey struct{}

//nolint:gochecknoglobals
var kCtxKey = ctxKey{}

// Config is the configuration for the middleware.
type Config struct {
	Logger *slog.Logger

	// Passthrough controls whether the request should be failed
	// on unauthorized access.
	Passthrough bool
}

// NewConfig returns a new configuration for Middleware.
func NewConfig(opts ...func(*Config)) *Config {
	//nolint:exhaustruct
	config := Config{}
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()
	config.assert()

	return &config
}

func (c *Config) defaults() {
	if c.Logger == nil {
		c.Logger = shield.DefaultLogger
	}
}

func (c *Config) assert() {
	debug.Assert(c.Logger != nil, "Logger must be set")
}

// Middleware returns a middleware that authenticates the user and
// adds it to the request context.
//
// If the user is not authenticated, the error handler is called.
//
// If config is nil, the default config is used.
func Middleware[T any](
	authenticator shieldstrategy.Authenticator[T],
	errorHandler httperror.ErrorHandler,
	config *Config,
) func(http.Handler) http.Handler {
	debug.Assert(authenticator != nil, "authenticator must be set")
	debug.Assert(errorHandler != nil, "errorHandler must be set")

	if config == nil {
		config = NewConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := authenticator.Authenticate(w, r)
			if err != nil {
				// If Passthrough is set ignore the error and continue.
				if !config.Passthrough {
					errorHandler.ServeHTTP(
						w,
						r,
						httperror.FromError(
							err,
							http.StatusUnauthorized,
							"unauthorized access",
						),
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

// RedirectAuthenticatedUserMiddleware redirects the user to the
// provided URL if the user is authenticated.
//
// Make sure to use the Middleware before adding this one.
func RedirectAuthenticatedUserMiddleware(redirectURL string) httpmiddleware.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsAuthenticated(r.Context()) {
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
