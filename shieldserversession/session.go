// Package shieldserversession implements a server-side session management strategy for
// managing user sessions.
//
// The implementation uses a PostgreSQL database to store session data.
package shieldserversession

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/foundations/dbsql"
	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/http/httpcookie"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/logutil"
	"go.inout.gg/shield/shieldmfa"
	"go.inout.gg/shield/shielduser"
)

var (
	_ shielduser.Authenticator[any, any] = (*sessionStrategy[any, any])(nil)
	_ shielduser.Impersonator[any, any]  = (*sessionStrategy[any, any])(nil)
)

//nolint:gochecknoglobals
var d = debug.Debuglog("shieldserversession")

const (
	DefaultCookieName             = "usid"
	DefaultExpiresIn              = time.Hour * 12
	DefaultImpersonationExpiresIn = time.Minute * 15
	MaxImpersonationExpiresIn     = time.Minute * 30
)

// TODO: implement session caching.
type sessionStrategy[U, S any] struct {
	dbtx   shield.DBTX
	config Config[U, S]
}

type Hooker[U, S any] interface {
	OnSessionIssue(
		context.Context,
		*shielduser.User[U],
		*shielduser.Session[S],
		pgx.Tx,
	) (*shielduser.Session[S], error)

	// OnSessionAuthenticate allows to hook into the session authentication process.
	OnSessionAuthenticate(
		context.Context,
		*shielduser.Session[S],
		pgx.Tx,
	) (*shielduser.Session[S], error)

	// OnLogout allows to hook into the session logout process.
	OnLogout(
		ctx context.Context,
		userID, sessionID int64,
		tx pgx.Tx,
	) error

	// OnExpireSessions allows to hook into session expiration process.
	OnExpireSessions(
		ctx context.Context,
		userID, sessionID int64,
	) error
}

type Config[U, S any] struct {
	Logger *slog.Logger

	Hooker Hooker[U, S]

	CookieName             string        // optional (default: "usid")
	ExpiresIn              time.Duration // optional (default: 12h)
	ImpersonationExpiresIn time.Duration // optional (default: 15m)
}

func (c *Config[_, _]) defaults() {
	c.CookieName = cmp.Or(c.CookieName, DefaultCookieName)
	c.ExpiresIn = cmp.Or(c.ExpiresIn, DefaultExpiresIn)
	c.ImpersonationExpiresIn = cmp.Or(
		c.ImpersonationExpiresIn,
		DefaultImpersonationExpiresIn,
	)

	debug.Assert(c.CookieName != "", "c.CookieName is required")
	debug.Assert(
		c.ExpiresIn > 0,
		"config.ExpiresIn must be positive time.Duration",
	)
	debug.Assert(
		c.ImpersonationExpiresIn > 0,
		"config.ImpersonationExpiresIn must be positive time.Duration",
	)
	debug.Assert(
		c.ImpersonationExpiresIn <= MaxImpersonationExpiresIn,
		"config.ImpersonationExpiresIn must be at most 30m",
	)
}

// WithHooker sets a session hooker for a given config.
func WithHooker[U, S any](h Hooker[U, S]) func(*Config[U, S]) {
	return func(c *Config[U, S]) { c.Hooker = h }
}

// WithImpersonationExpiresIn sets the impersonation expires in duration for a given config.
func WithImpersonationExpiresIn[U, S any](d time.Duration) func(*Config[U, S]) {
	return func(c *Config[U, S]) { c.ImpersonationExpiresIn = d }
}

// New creates a new session authenticator.
//
// The session authenticator uses a DB to store sessions and a cookie to
// store the session ID.
func New[U, S any](
	dbtx shield.DBTX,
	opts ...func(*Config[U, S]),
) shielduser.Authenticator[U, S] {
	var config Config[U, S]
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()

	debug.Assert(dbtx != nil, "dbtx is required")

	return &sessionStrategy[U, S]{
		dbtx:   dbtx,
		config: config,
	}
}

func (s *sessionStrategy[U, S]) Issue(
	w http.ResponseWriter,
	r *http.Request,
	user *shielduser.User[U],
) (*shielduser.Session[S], error) {
	ctx := r.Context()

	if user == nil {
		return nil, fmt.Errorf("shieldserversession: user is required")
	}

	isMFARequired := true

	mfas, err := shieldmfa.UserMFA(ctx, s.dbtx, user.ID)
	if err != nil {
		if errors.Is(err, shieldmfa.ErrNoMFAMethods) {
			isMFARequired = false
		} else {
			return nil, fmt.Errorf(
				"shieldserversession: failed to get MFA: %w",
				err,
			)
		}
	}

	expiresAt := time.Now().Add(s.config.ExpiresIn)

	tx, err := s.dbtx.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"shieldserversession: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	sess, err := s.issueSessionTx(ctx, user, expiresAt, isMFARequired, nil, tx)
	if err != nil {
		return sess, err
	}

	if err := tx.Commit(ctx); err != nil {
		return sess, fmt.Errorf(
			"shieldserversession: failed to commit transaction: %w",
			err,
		)
	}

	httpcookie.Set(
		w,
		s.config.CookieName,
		strconv.FormatInt(sess.ID, 10),
		httpcookie.WithHTTPOnly,
		httpcookie.WithExpiresIn(s.config.ExpiresIn),
	)

	if isMFARequired {
		return sess, shieldmfa.NewUserMFARequiredError(user.ID, mfas)
	}

	return sess, nil
}

func (s *sessionStrategy[U, S]) Impersonate(
	w http.ResponseWriter,
	r *http.Request,
	actorSession *shielduser.Session[S],
	targetUser *shielduser.User[U],
) (*shielduser.Session[S], error) {
	ctx := r.Context()

	if actorSession == nil {
		return nil, fmt.Errorf("shieldserversession: actor session is required")
	}

	if targetUser == nil {
		return nil, fmt.Errorf("shieldserversession: target user is required")
	}

	if actorSession.IsMFARequired {
		return nil, shield.ErrMFARequired
	}

	if actorSession.ImpersonatedBy != nil {
		return nil, fmt.Errorf(
			"shieldserversession: nested impersonation is not supported",
		)
	}

	tx, err := s.dbtx.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"shieldserversession: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	expiresAt := time.Now().Add(s.config.ImpersonationExpiresIn)
	impersonatedBy := actorSession.UserID

	sess, err := s.issueSessionTx(
		ctx,
		targetUser,
		expiresAt,
		false,
		&impersonatedBy,
		tx,
	)
	if err != nil {
		return sess, err
	}

	if err := tx.Commit(ctx); err != nil {
		return sess, fmt.Errorf(
			"shieldserversession: failed to commit transaction: %w",
			err,
		)
	}

	httpcookie.Set(
		w,
		s.config.CookieName,
		strconv.FormatInt(sess.ID, 10),
		httpcookie.WithHTTPOnly,
		httpcookie.WithExpiresIn(s.config.ImpersonationExpiresIn),
	)

	return sess, nil
}

func (s *sessionStrategy[U, S]) issueSessionTx(
	ctx context.Context,
	user *shielduser.User[U],
	expiresAt time.Time,
	isMFARequired bool,
	impersonatedBy *int64,
	tx pgx.Tx,
) (*shielduser.Session[S], error) {
	sess := &shielduser.Session[S]{}

	sessionID, err := dbsqlc.New().CreateUserSession(
		ctx,
		tx,
		dbsqlc.CreateUserSessionParams{
			UserID:         user.ID,
			ExpiresAt:      expiresAt,
			IsMfaRequired:  isMFARequired,
			ImpersonatedBy: impersonatedBy,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"shieldserversession: failed to create session: %w",
			err,
		)
	}

	d(
		"issuing a new session with id=%v for user=%v, expiring at=%v",
		sessionID,
		user.ID,
		expiresAt,
	)

	sess.ID = sessionID
	sess.ExpiresAt = expiresAt
	sess.UserID = user.ID
	sess.IsMFARequired = isMFARequired
	sess.ImpersonatedBy = impersonatedBy

	if s.config.Hooker != nil {
		sess, err = s.config.Hooker.OnSessionIssue(ctx, user, sess, tx)
		if err != nil {
			return sess, fmt.Errorf(
				"shieldserversession: failed to create session: %w",
				err,
			)
		}
	}

	return sess, nil
}

func sessionFromDB[S any](dbSess dbsqlc.ShieldUserSession) *shielduser.Session[S] {
	return &shielduser.Session[S]{
		ID:             dbSess.ID,
		ExpiresAt:      dbSess.ExpiresAt,
		UserID:         dbSess.UserID,
		ImpersonatedBy: dbSess.ImpersonatedBy,
		IsMFARequired:  dbSess.IsMfaRequired,
	}
}

func (s *sessionStrategy[U, S]) Authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (*shielduser.Session[S], error) {
	ctx := r.Context()

	sessionIDStr := httpcookie.Get(r, s.config.CookieName)
	if sessionIDStr == "" {
		return nil, shield.ErrUnauthenticatedUser
	}

	sessionID, err := strconv.ParseInt(sessionIDStr, 10, 64)
	if err != nil {
		httpcookie.Delete(w, r, s.config.CookieName)
		return nil, shield.ErrUnauthenticatedUser
	}

	tx, err := s.dbtx.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"shieldserversession: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	dbSess, err := dbsqlc.New().FindActiveSessionByID(ctx, tx, sessionID)
	if err != nil {
		if dbsql.IsNotFoundError(err) {
			logutil.Log(ctx, s.config.Logger, slog.LevelError,
				"No sessions found with the given ID",
				slog.Int64("session_id", sessionID),
				slog.Any("error", err),
			)

			httpcookie.Delete(w, r, s.config.CookieName)

			return nil, shield.ErrUnauthenticatedUser
		}

		return nil, fmt.Errorf(
			"shieldserversession: failed to find user session: %w",
			err,
		)
	}

	sess := sessionFromDB[S](dbSess)

	if sess.IsMFARequired {
		return sess, shield.ErrMFARequired
	}

	if s.config.Hooker != nil {
		sess, err = s.config.Hooker.OnSessionAuthenticate(ctx, sess, tx)
		if err != nil {
			return sess, fmt.Errorf(
				"shieldserversession: failed to authenticate session: %w",
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return sess, fmt.Errorf(
			"shieldserversession: failed to commit transaction: %w",
			err,
		)
	}

	return sess, nil
}

func (s *sessionStrategy[U, S]) ExpireSessions(
	ctx context.Context,
	tx pgx.Tx,
) error {
	sess, err := shielduser.FromContext[S](ctx)
	if err != nil {
		return fmt.Errorf(
			"shieldserversession: failed to retrieve session from a given context: %w",
			err,
		)
	}

	_, err = dbsqlc.New().
		ExpireSomeSessionsByUserID(ctx, tx, dbsqlc.ExpireSomeSessionsByUserIDParams{
			UserID:     sess.UserID,
			EvictedBy:  &sess.UserID,
			SessionIds: []int64{sess.ID},
		})
	if err != nil {
		return fmt.Errorf(
			"shieldserversession: failed to expire sessions: %w",
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
				"shieldserversession: failed to hook into session expiration: %w",
				err,
			)
		}
	}

	return nil
}
