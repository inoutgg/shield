package session

import (
	"net/http"

	"go.inout.gg/foundations/http/cookie"
	"go.inout.gg/foundations/http/httperror"
	"go.inout.gg/shield"
	"go.inout.gg/shield/db/driver"
	"go.inout.gg/shield/shielduser"
)

// LogoutHandler is a handler that logs out the user and deletes the session.
type LogoutHandler struct {
	driver driver.Driver
	config *Config
}

func NewLogoutHandler(driver driver.Driver, config *Config) *LogoutHandler {
	return &LogoutHandler{driver, config}
}

func (h *LogoutHandler) HandleLogout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	q := h.driver.Queries()

	usr := shielduser.FromRequest[any](r)
	if usr == nil {
		return httperror.FromError(shield.ErrUnauthenticatedUser, http.StatusUnauthorized)
	}

	if _, err := q.ExpireSessionByID(ctx, usr.ID); err != nil {
		return httperror.FromError(err, http.StatusInternalServerError)
	}

	// Delete session cookie.
	cookie.Delete(w, r, h.config.CookieName)

	return nil
}
