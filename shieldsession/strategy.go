package shieldsession

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"go.jetify.com/typeid/v2"

	"go.inout.gg/shield"
)

// Session is a session that is issued when a user is authenticated.
type Session[T any] struct {
	ExpiresAt time.Time
	T         *T
	UserID    typeid.TypeID
	ID        typeid.TypeID
}

// Authenticator authenticates the user.
type Authenticator[U, S any] interface {
	// Issue creates a new session for the given user.
	//
	// Session might be partially issued, meaning that the session is created but
	// not fully authenticated, i.e., when user is required MFA authentication.
	Issue(
		http.ResponseWriter,
		*http.Request,
		shield.User[U],
	) (Session[S], error)

	// Authenticate authenticates the user.
	//
	// It returns a session if the user is authenticated, otherwise it returns
	// a shield.ErrUnauthenticatedUser error.
	Authenticate(http.ResponseWriter, *http.Request) (Session[S], error)

	// ExpireSessions closes all sessions, but one assigned to a the context.
	//
	// If authenticator doesn't support a session expiration it will return
	// errors.ErrUnsupported error.
	//
	// If there is no session assigned to a request shield.ErrUnauthenticatedUser is returned.
	//
	// ExpireSessions method is used by shieldpassword.Handler for closing all
	// sessions on password change.
	ExpireSessions(context.Context, pgx.Tx) error
}
