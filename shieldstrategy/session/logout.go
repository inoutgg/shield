package session

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/http/cookie"
	"go.inout.gg/foundations/http/httperror"
	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/shielduser"
)

// LogoutHandler is a handler that logs out the user and deletes the session.
type LogoutHandler struct {
	pool   *pgxpool.Pool
	config *Config
}

func NewLogoutHandler(pool *pgxpool.Pool, config *Config) *LogoutHandler {
	return &LogoutHandler{pool, config}
}

func (h *LogoutHandler) HandleLogout(w http.ResponseWriter, r *http.Request) error {
	queries := dbsqlc.New()
	ctx := r.Context()

	usr := shielduser.FromRequest[any](r)
	if usr == nil {
		return httperror.FromError(shield.ErrUnauthenticatedUser, http.StatusUnauthorized)
	}

	if _, err := queries.ExpireSessionByID(ctx, h.pool, usr.ID); err != nil {
		return httperror.FromError(err, http.StatusInternalServerError)
	}

	// Delete session cookie.
	cookie.Delete(w, r, h.config.CookieName)

	return nil
}
