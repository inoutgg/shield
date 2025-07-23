package shieldsession

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httperror"
	"go.inout.gg/foundations/http/httpmiddleware"

	"go.inout.gg/shield"
)

//nolint:gochecknoglobals
var d = debug.Debuglog("shield/shielduser")

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

// WithPassthrough returns a function that sets the Passthrough field of the Config.
func WithPassthrough() func(*Config) {
	return func(c *Config) { c.Passthrough = true }
}

// NewConfig returns a new configuration for Middleware.
func NewConfig(opts ...func(*Config)) *Config {
	var config Config
	for _, opt := range opts {
		opt(&config)
	}

	config.Logger = cmp.Or(config.Logger, shield.DefaultLogger)

	debug.Assert(config.Logger != nil, "logger must be set")

	return &config
}

// Middleware returns a middleware that authenticates the user and
// adds it to the request context.
//
// If the user is not authenticated, the error handler is called.
//
// If config is nil, the default config is used.
//
// If config.PassThrough is set, the middleware will not fail the request
// on unauthorized access and instead will continue processing the request.
func Middleware[U, S any](
	authenticator Authenticator[U, S],
	errorHandler httperror.ErrorHandler,
	config *Config,
) httpmiddleware.MiddlewareFunc {
	debug.Assert(authenticator != nil, "authenticator must be set")
	debug.Assert(errorHandler != nil, "errorHandler must be set")

	if config == nil {
		config = NewConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				nextReq := r

				sess, err := authenticator.Authenticate(w, r)
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
				} else {
					ctx := context.WithValue(r.Context(), kCtxKey, &sess)
					nextReq = r.WithContext(ctx)
				}

				next.ServeHTTP(
					w,
					nextReq,
				)
			},
		)
	}
}

// RedirectAuthenticatedUserMiddleware redirects the user to the
// provided URL if the user is authenticated.
//
// Make sure to use the Middleware before adding this one.
func RedirectAuthenticatedUserMiddleware(
	redirectURL string,
) httpmiddleware.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if IsAuthenticated(r.Context()) {
					d("redirecting authenticated user")

					http.Redirect(
						w,
						r,
						redirectURL,
						http.StatusTemporaryRedirect,
					)

					return
				}

				next.ServeHTTP(w, r)
			},
		)
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
// Make sure to use the Middleware before calling this function.
func FromContext[S any](ctx context.Context) (*Session[S], error) {
	if sess, ok := ctx.Value(kCtxKey).(*Session[S]); ok {
		return sess, nil
	}

	return nil, shield.ErrUnauthenticatedUser
}

// IsAuthenticated returns true if the user is authorized.
func IsAuthenticated(ctx context.Context) bool {
	return ctx.Value(kCtxKey) != nil
}
