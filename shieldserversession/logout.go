package shieldserversession

import (
	"fmt"
	"net/http"

	"go.inout.gg/foundations/http/httpcookie"
	"go.inout.gg/foundations/http/httperror"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/shielduser"
)

// LogoutHandler is a handler that logs out the user and deletes the session.
type LogoutHandler[U, S any] struct {
	dbtx   shield.DBTX
	config Config[U, S]
}

func NewLogoutHandler[U, S any](
	dbtx shield.DBTX,
	opts ...func(*Config[U, S]),
) *LogoutHandler[U, S] {
	var config Config[U, S]
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	return &LogoutHandler[U, S]{dbtx, config}
}

// Logout logs out the user and deletes the session.
func (h *LogoutHandler[U, S]) Logout(
	w http.ResponseWriter,
	r *http.Request,
) error {
	ctx := r.Context()

	sess, err := shielduser.FromRequest[S](r)
	if err != nil {
		return httperror.FromError(err, http.StatusUnauthorized)
	}

	tx, err := h.dbtx.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shieldserversession: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	sessID, err := dbsqlc.New().ExpireSessionByID(ctx, tx, sess.ID)
	if err != nil {
		return fmt.Errorf(
			"shieldserversession: failed to expire session: %w",
			err,
		)
	}

	hooker := h.config.Hooker
	if hooker != nil {
		if err := hooker.OnLogout(ctx, sess.UserID, sessID, tx); err != nil {
			return fmt.Errorf(
				"shieldserversession: failed to hook logout: %w",
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shieldserversession: failed to commit transaction: %w",
			err,
		)
	}

	httpcookie.Delete(w, r, h.config.CookieName)

	return nil
}
