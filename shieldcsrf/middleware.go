// Package csrf implements a CSRF protection middleware based on the double
// submit cookie pattern.
package shieldcsrf

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"go.inout.gg/foundations/http/httperror"
	"go.inout.gg/foundations/http/httpmiddleware"
)

type ctxKey struct{}

//nolint:gochecknoglobals
var kCtxKey = ctxKey{}

var ErrNoChecksumSecret = errors.New("shield/csrf: checksum secret is not provided")

const (
	DefaultFieldName  = "csrf_token"
	DefaultHeaderName = "X-Csrf-Token"
	DefaultCookieName = "csrf_token"
)

const DefaultTokenLength = 32

// Config is the configuration for the CSRF middleware.
type Config struct {
	ErrorHandler   httperror.ErrorHandler
	ChecksumSecret string
	HeaderName     string
	FieldName      string
	CookieName     string
	IgnoredMethods []string
	TokenLength    int
	CookieSameSite http.SameSite
	CookieSecure   bool
}

// Middleware returns a middleware that adds CSRF token to the request context.
func Middleware(secret string, config ...func(*Config)) (httpmiddleware.MiddlewareFunc, error) {
	//nolint:exhaustruct
	cfg := Config{
		IgnoredMethods: []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodOptions,
			http.MethodTrace,
		},
		HeaderName:     DefaultHeaderName,
		FieldName:      DefaultFieldName,
		CookieName:     DefaultCookieName,
		TokenLength:    DefaultTokenLength,
		CookieSameSite: http.SameSiteLaxMode,
	}
	for _, f := range config {
		f(&cfg)
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = httperror.DefaultErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokConfig := &tokenConfig{
				ChecksumSecret: secret,
				TokenLength:    cfg.TokenLength,
				HeaderName:     cfg.HeaderName,
				FieldName:      cfg.FieldName,
				CookieName:     cfg.CookieName,
				CookieSameSite: cfg.CookieSameSite,
				CookieSecure:   cfg.CookieSecure,
			}

			tok, err := newToken(tokConfig)
			if err != nil {
				cfg.ErrorHandler.ServeHTTP(w, r, err)
				return
			}

			newCtx := context.WithValue(r.Context(), kCtxKey, tok)

			if slices.Contains(cfg.IgnoredMethods, r.Method) {
				next.ServeHTTP(w, r.WithContext(newCtx))
				return
			}

			err = validateRequest(r, tokConfig)
			if err != nil {
				err := httperror.FromError(err, http.StatusForbidden, "invalid CSRF token")
				cfg.ErrorHandler.ServeHTTP(w, r, err)

				return
			}

			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}, nil
}

// FromRequest returns the CSRF token associated with the given HTTP request.
func FromRequest(r *http.Request) (*Token, error) {
	return FromContext(r.Context())
}

// FromContext returns the CSRF token associated with the given context.
func FromContext(ctx context.Context) (*Token, error) {
	tok, ok := ctx.Value(kCtxKey).(*Token)
	if !ok {
		return nil, errors.New("shield/csrf: unable to retrieve request context")
	}

	return tok, nil
}

// SetToken sets the CSRF token in the given HTTP response via cookie.
func SetToken(w http.ResponseWriter, tok *Token) {
	http.SetCookie(w, tok.cookie())
}
