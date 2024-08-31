package session

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"go.inout.gg/shield"
	"go.inout.gg/shield/db/driver"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/strategy"
	"go.inout.gg/foundations/http/cookie"
	"go.inout.gg/shield/internal/uuidv7"
	"go.inout.gg/foundations/sql/db/dbutil"
)

var _ strategy.Authenticator[any] = (*sessionStrategy[any])(nil)

var (
	DefaultCookieName = "usid"
	DefaultExpiresIn  = time.Hour * 12
)

type sessionStrategy[T any] struct {
	driver driver.Driver
	config *Config
}

type Config struct {
	Logger *slog.Logger

	CookieName string        // optinal (default: "usid")
	ExpiresIn  time.Duration // optinal (default: 12h)
}

// New creates a new session authenticator.
//
// The sesion authenticator uses a DB to store sessions and a cookie to
// store the session ID.
func New[T any](driver driver.Driver, config ...func(*Config)) strategy.Authenticator[T] {
	cfg := &Config{
		Logger:     slog.Default().With("module", "shield/session"),
		CookieName: DefaultCookieName,
		ExpiresIn:  DefaultExpiresIn,
	}
	for _, c := range config {
		c(cfg)
	}

	return &sessionStrategy[T]{driver, cfg}
}

func (s *sessionStrategy[T]) Issue(
	w http.ResponseWriter,
	r *http.Request,
	user *authentication.User[T],
) (*strategy.Session[T], error) {
	ctx := r.Context()
	q := s.driver.Queries()
	sessionID := uuidv7.Must()
	expiresAt := time.Now().Add(s.config.ExpiresIn)
	_, err := q.CreateUserSession(ctx, dbsqlc.CreateUserSessionParams{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: pgtype.Timestamp{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("shield/session: failed to create session: %w", err)
	}

	cookie.Set(
		w,
		s.config.CookieName,
		s.encode(sessionID.String()),
		cookie.WithHttpOnly,
		cookie.WithExpiresIn(s.config.ExpiresIn),
	)

	return &strategy.Session[T]{
		ID:        sessionID,
		ExpiresAt: expiresAt,
		T:         nil,
	}, nil
}

func (s *sessionStrategy[T]) Authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (*strategy.Session[T], error) {
	ctx := r.Context()
	sessionIDStr := cookie.Get(r, s.config.CookieName)
	if sessionIDStr == "" {
		return nil, authentication.ErrUnauthorizedUser
	}

	sessionID, err := uuidv7.FromString(sessionIDStr)
	if err != nil {
		cookie.Delete(w, r, s.config.CookieName)
		return nil, authentication.ErrUnauthorizedUser
	}

	tx, err := s.driver.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/session: failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	q := tx.Queries()

	session, err := q.FindUserSessionByID(ctx, sessionID)
	if err != nil {
		if dbutil.IsNotFoundError(err) {
			s.config.Logger.Error(
				"No sessions found with given ID",
				slog.String("session_id", sessionID.String()),
				slog.Any("error", err),
			)

			cookie.Delete(w, r, s.config.CookieName)
			return nil, authentication.ErrUnauthorizedUser
		}

		s.config.Logger.Error(
			"Unable to find a session",
			slog.String("session_id", sessionID.String()),
			slog.Any("error", err),
		)

		return nil, fmt.Errorf("shield/session: failed to find user session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("shield/session: failed to commit transaction: %w", err)
	}

	return &strategy.Session[T]{
		ID:        session.ID,
		ExpiresAt: session.ExpiresAt.Time,
		T:         nil,
	}, nil
}
