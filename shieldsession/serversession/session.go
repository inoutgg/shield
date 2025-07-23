// Package session implements a server-side session management strategy for
// managing user sessions.
//
// The implementation uses a PostgreSQL database to store session data.
package serversession

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httpcookie"
	"go.inout.gg/foundations/sqldb"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/uuidv7"
	"go.inout.gg/shield/shieldsession"
)

var _ shieldsession.Authenticator[any, any] = (*sessionStrategy[any, any])(nil)

//nolint:gochecknoglobals
var d = debug.Debuglog("shield/session")

const (
	DefaultCookieName = "usid"
	DefaultExpiresIn  = time.Hour * 12
)

// TODO: implement session caching.
type sessionStrategy[U, S any] struct {
	pool   *pgxpool.Pool
	config *Config[U, S]
}

type Hooker[U, S any] interface {
	OnSessionIssue(
		context.Context,
		shield.User[U],
		shieldsession.Session[S],
		pgx.Tx,
	) (shieldsession.Session[S], error)

	// OnSessionAuthenticate allows to hook into the session authentication process.
	OnSessionAuthenticate(
		context.Context,
		shieldsession.Session[S],
		pgx.Tx,
	) (shieldsession.Session[S], error)

	// OnLogout allows to hook into the session logout process.
	OnLogout(
		ctx context.Context,
		userID, sessionID uuid.UUID,
		tx pgx.Tx,
	) error

	// OnExpireSessions allows to hook into session expiration process.
	OnExpireSessions(ctx context.Context, userID, sessionID uuid.UUID) error
}

type Config[U, S any] struct {
	Logger *slog.Logger

	Hooker Hooker[U, S]

	CookieName string        // optional (default: "usid")
	ExpiresIn  time.Duration // optional (default: 12h)
}

// WithHooker sets a session hooker for a given config.
func WithHooker[U, S any](h Hooker[U, S]) func(*Config[U, S]) {
	return func(c *Config[U, S]) { c.Hooker = h }
}

// NewConfig creates a new session configuration.
func NewConfig[U, S any](opts ...func(*Config[U, S])) *Config[U, S] {
	var config Config[U, S]
	for _, opt := range opts {
		opt(&config)
	}

	config.Logger = cmp.Or(config.Logger, shield.DefaultLogger)
	config.CookieName = cmp.Or(config.CookieName, DefaultCookieName)
	config.ExpiresIn = cmp.Or(config.ExpiresIn, DefaultExpiresIn)

	debug.Assert(config.Logger != nil, "config.Logger is required")
	debug.Assert(config.CookieName != "", "config.CookieName is required")
	debug.Assert(
		config.ExpiresIn > 0,
		"config.ExpiresIn must be positive time.Duration",
	)

	return &config
}

// New creates a new session authenticator.
//
// The session authenticator uses a DB to store sessions and a cookie to
// store the session ID.
func New[U, S any](
	pool *pgxpool.Pool,
	config *Config[U, S],
) shieldsession.Authenticator[U, S] {
	if config == nil {
		config = NewConfig[U, S]()
	}

	debug.Assert(pool != nil, "pool is required")

	return &sessionStrategy[U, S]{
		pool:   pool,
		config: config,
	}
}

func (s *sessionStrategy[U, S]) Issue(
	w http.ResponseWriter,
	r *http.Request,
	user shield.User[U],
) (shieldsession.Session[S], error) {
	ctx := r.Context()
	sessionID := uuidv7.Must()
	expiresAt := time.Now().Add(s.config.ExpiresIn)

	d(
		"issuing a new session with id=%v for user=%v, expiring at=%v",
		sessionID,
		user.ID,
		expiresAt,
	)

	var sess shieldsession.Session[S]

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sess, fmt.Errorf(
			"shield/session: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	mfas, err := user.MFA(ctx, tx)
	if err != nil {
		return sess, fmt.Errorf(
			"shield/session: failed to get MFA: %w",
			err,
		)
	}

	isMFARequired := len(mfas) > 0

	_, err = dbsqlc.New().
		CreateUserSession(ctx, tx, dbsqlc.CreateUserSessionParams{
			ID:            sessionID,
			UserID:        user.ID,
			ExpiresAt:     expiresAt,
			IsMfaRequired: isMFARequired,
		})
	if err != nil {
		return sess, fmt.Errorf(
			"shield/session: failed to create session: %w",
			err,
		)
	}

	sess.ID = sessionID
	sess.ExpiresAt = expiresAt
	sess.UserID = user.ID

	if s.config.Hooker != nil {
		sess, err = s.config.Hooker.OnSessionIssue(ctx, user, sess, tx)
		if err != nil {
			return sess, fmt.Errorf(
				"shield/session: failed to create session: %w",
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return sess, fmt.Errorf(
			"shield/session: failed to commit transaction: %w",
			err,
		)
	}

	httpcookie.Set(
		w,
		s.config.CookieName,
		sessionID.String(),
		httpcookie.WithHttpOnly,
		httpcookie.WithExpiresIn(s.config.ExpiresIn),
	)

	return sess, nil
}

func (s *sessionStrategy[U, S]) Authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (shieldsession.Session[S], error) {
	ctx := r.Context()

	var sess shieldsession.Session[S]

	sessionIDStr := httpcookie.Get(r, s.config.CookieName)
	if sessionIDStr == "" {
		return sess, shield.ErrUnauthenticatedUser
	}

	sessionID, err := uuidv7.FromString(sessionIDStr)
	if err != nil {
		httpcookie.Delete(w, r, s.config.CookieName)
		return sess, shield.ErrUnauthenticatedUser
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sess, fmt.Errorf(
			"shield/session: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	dbSess, err := dbsqlc.New().FindActiveSessionByID(ctx, tx, sessionID)
	if err != nil {
		if sqldb.IsNotFoundError(err) {
			s.config.Logger.ErrorContext(
				ctx,
				"No sessions found with the given ID",
				slog.String("session_id", sessionID.String()),
				slog.Any("error", err),
			)

			httpcookie.Delete(w, r, s.config.CookieName)

			return sess, shield.ErrUnauthenticatedUser
		}

		return sess, fmt.Errorf(
			"shield/session: failed to find user session: %w",
			err,
		)
	}

	if dbSess.IsMfaRequired {
		return sess, shield.ErrMFARequired
	}

	sess.ID = dbSess.ID
	sess.ExpiresAt = dbSess.ExpiresAt
	sess.UserID = dbSess.UserID

	if s.config.Hooker != nil {
		sess, err = s.config.Hooker.OnSessionAuthenticate(ctx, sess, tx)
		if err != nil {
			return sess, fmt.Errorf(
				"shield/session: failed to authenticate session: %w",
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return sess, fmt.Errorf(
			"shield/session: failed to commit transaction: %w",
			err,
		)
	}

	return sess, nil
}

func (s *sessionStrategy[U, S]) ExpireSessions(
	ctx context.Context,
	tx pgx.Tx,
) error {
	sess, err := shieldsession.FromContext[S](ctx)
	if err != nil {
		return fmt.Errorf(
			"shield/session: failed to retrieve session from a given context: %w",
			err,
		)
	}

	_, err = dbsqlc.New().
		ExpireSomeSessionsByUserID(ctx, tx, dbsqlc.ExpireSomeSessionsByUserIDParams{
			UserID:     sess.UserID,
			EvictedBy:  sess.UserID,
			SessionIds: []uuid.UUID{sess.ID},
		})
	if err != nil {
		return fmt.Errorf(
			"shield/session: failed to expire sessions: %w",
			err,
		)
	}

	if s.config.Hooker != nil {
		d(
			"hooking into session expiration: %v %v",
			sess.UserID,
			sess.ID,
		)

		if err := s.config.Hooker.OnExpireSessions(ctx, sess.UserID, sess.ID); err != nil {
			return fmt.Errorf(
				"shield/session: failed to hook into session expiration: %w",
				err,
			)
		}
	}

	return nil
}
