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
	Resolver     func(string) string
	CookieName   string
	CookieExpiry time.Duration
}

func (c *Config) defaults() {
	if c.Resolver == nil {
		c.Resolver = DefaultResolver
	}

	c.CookieName = cmp.Or(c.CookieName, DefaultCookieName)
	c.CookieExpiry = cmp.Or(c.CookieExpiry, DefaultCookieExpiry)
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
