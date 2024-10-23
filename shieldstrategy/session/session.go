package session

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/http/cookie"
	"go.inout.gg/foundations/sqldb"
	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/uuidv7"
	"go.inout.gg/shield/shieldstrategy"
)

var _ shieldstrategy.Authenticator[any] = (*sessionStrategy[any])(nil)

var (
	DefaultCookieName = "usid"
	DefaultExpiresIn  = time.Hour * 12
)

type sessionStrategy[T any] struct {
	config *Config
	pool   *pgxpool.Pool
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
func New[T any](pool *pgxpool.Pool, opts ...func(*Config)) shieldstrategy.Authenticator[T] {
	config := &Config{
		CookieName: DefaultCookieName,
		ExpiresIn:  DefaultExpiresIn,
	}
	for _, opt := range opts {
		opt(config)
	}

	if config.Logger != nil {
		config.Logger = slog.Default()
	}

	return &sessionStrategy[T]{config, pool}
}

func (s *sessionStrategy[T]) Issue(
	w http.ResponseWriter,
	r *http.Request,
	user *shield.User[T],
) (*shieldstrategy.Session[T], error) {
	ctx := r.Context()
	queries := dbsqlc.New()

	sessionID := uuidv7.Must()
	expiresAt := time.Now().Add(s.config.ExpiresIn)
	_, err := queries.CreateUserSession(ctx, s.pool, dbsqlc.CreateUserSessionParams{
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
		sessionID.String(),
		cookie.WithHttpOnly,
		cookie.WithExpiresIn(s.config.ExpiresIn),
	)

	return &shieldstrategy.Session[T]{
		ID:        sessionID,
		ExpiresAt: expiresAt,
		T:         nil,
	}, nil
}

func (s *sessionStrategy[T]) Authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (*shieldstrategy.Session[T], error) {
	queries := dbsqlc.New()
	ctx := r.Context()

	sessionIDStr := cookie.Get(r, s.config.CookieName)
	if sessionIDStr == "" {
		return nil, shield.ErrUnauthenticatedUser
	}

	sessionID, err := uuidv7.FromString(sessionIDStr)
	if err != nil {
		cookie.Delete(w, r, s.config.CookieName)
		return nil, shield.ErrUnauthenticatedUser
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/session: failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	session, err := queries.FindUserSessionByID(ctx, tx, sessionID)
	if err != nil {
		if sqldb.IsNotFoundError(err) {
			s.config.Logger.Error(
				"No sessions found with given ID",
				slog.String("session_id", sessionID.String()),
				slog.Any("error", err),
			)

			cookie.Delete(w, r, s.config.CookieName)
			return nil, shield.ErrUnauthenticatedUser
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

	return &shieldstrategy.Session[T]{
		ID:        session.ID,
		ExpiresAt: session.ExpiresAt.Time,
		T:         nil,
	}, nil
}
