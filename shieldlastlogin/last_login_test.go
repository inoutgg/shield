package shieldlastlogin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func handle[S any](r *http.Request, opts ...func(*Config)) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()

	m := Middleware[S](opts...)
	h := m(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	}))

	h.ServeHTTP(w, r)

	return w
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("no session does not set cookie", func(t *testing.T) {
		t.Parallel()

		w := handle[any](httptest.NewRequest(http.MethodGet, "/", nil))

		for _, c := range w.Result().Cookies() {
			assert.NotEqual(t, DefaultCookieName, c.Name,
				"expected no last_login cookie to be set")
		}
	})
}

func TestFromRequest(t *testing.T) {
	t.Parallel()

	t.Run("returns empty string when no cookie is set", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)

		assert.Empty(t, FromRequest(r))
	})

	t.Run("returns cookie value with default name", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: "password"})

		assert.Equal(t, "password", FromRequest(r))
	})

	t.Run("returns cookie value with custom name", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: "custom_login", Value: "oauth"})

		assert.Equal(t, "oauth", FromRequest(r, "custom_login"))
	})

	t.Run("returns empty string when cookie name does not match", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: "other_cookie", Value: "password"})

		assert.Empty(t, FromRequest(r))
	})
}
