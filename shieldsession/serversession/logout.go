package serversession

import (
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/http/httpcookie"
	"go.inout.gg/foundations/http/httperror"

	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/shieldsession"
)

// LogoutHandler is a handler that logs out the user and deletes the session.
type LogoutHandler[U, S any] struct {
	pool   *pgxpool.Pool
	config *Config[U, S]
}

func NewLogoutHandler[U, S any](
	pool *pgxpool.Pool,
	config *Config[U, S],
) *LogoutHandler[U, S] {
	if config == nil {
		config = NewConfig[U, S]()
	}

	return &LogoutHandler[U, S]{pool, config}
}

// Logout logs out the user and deletes the session.
func (h *LogoutHandler[U, S]) Logout(
	w http.ResponseWriter,
	r *http.Request,
) error {
	ctx := r.Context()

	sess, err := shieldsession.FromRequest[S](r)
	if err != nil {
		return httperror.FromError(err, http.StatusUnauthorized)
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shield/session: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	sessID, err := dbsqlc.New().ExpireSessionByID(ctx, tx, sess.ID)
	if err != nil {
		return fmt.Errorf(
			"shield/session: failed to expire session: %w",
			err,
		)
	}

	hooker := h.config.Hooker
	if hooker != nil {
		if err := hooker.OnLogout(ctx, sess.UserID, sessID, tx); err != nil {
			return fmt.Errorf(
				"shield/session: failed to hook logout: %w",
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shield/session: failed to commit transaction: %w",
			err,
		)
	}

	httpcookie.Delete(w, r, h.config.CookieName)

	return nil
}
