package shieldlastlogin

import (
	"cmp"
	"net/http"
	"time"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httpcookie"
	"go.inout.gg/foundations/http/httpmiddleware"

	"go.inout.gg/shield/shielduser"
)

var (
	DefaultCookieName   = "last_login"                       //nolint:gochecknoglobals
	DefaultCookieExpiry = 30 * 24 * time.Hour                //nolint:gochecknoglobals
	DefaultResolver     = func(s string) string { return s } //nolint:gochecknoglobals
)

type Config struct {
	// Resolver is used to resolve the last login method from the user's session
	// to the internal method.
	//
	// Defaults to DefaultResolver, which is an identity function.
	Resolver func(string) string // optional.

	// CookieName is the name of the cookie used to store the last login method.
	//
	// Defaults to DefaultCookieName.
	CookieName string // optional

	// CookieExpiry is the duration for which the cookie should be valid.
	//
	// Defaults to DefaultCookieExpiry.
	CookieExpiry time.Duration // optional
}

func (c *Config) defaults() {
	if c.Resolver == nil {
		c.Resolver = DefaultResolver
	}

	c.CookieName = cmp.Or(c.CookieName, DefaultCookieName)
	c.CookieExpiry = cmp.Or(c.CookieExpiry, DefaultCookieExpiry)
}

// FromRequest retrieves the last login method from the request cookie.
//
// It returns an empty string if no last login method is set.
func FromRequest(r *http.Request, cookieName ...string) string {
	name := DefaultCookieName
	if len(cookieName) > 0 {
		name = cookieName[0]
	}

	return httpcookie.Get(r, name)
}

// Middleware tracks the last login method a user used. It helps to
// improve UX by providing helpful information guiding users to
// the right login method.
func Middleware[S any](opts ...func(*Config)) httpmiddleware.MiddlewareFunc {
	var cfg Config
	for _, opt := range opts {
		opt(&cfg)
	}

	cfg.defaults()

	debug.Assert(cfg.Resolver != nil, "expected cfg.Resolver to be set")

	return httpmiddleware.MiddlewareFunc(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := shielduser.FromRequest[S](r)
			if err != nil {
				next.ServeHTTP(w, r)

				return
			}

			// If no session is found, skip tracking it.
			if sess.Method == "" {
				next.ServeHTTP(w, r)

				return
			}

			httpcookie.Set(
				w,
				cfg.CookieName,
				cfg.Resolver(sess.Method),
				httpcookie.WithExpiresIn(cfg.CookieExpiry))

			next.ServeHTTP(w, r)
		})
	})
}
