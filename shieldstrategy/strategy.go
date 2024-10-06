package shieldstrategy

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.inout.gg/shield"
)

type Session[T any] struct {
	// ID is the session ID.
	ID uuid.UUID

	// ExpiresAt is the time at which the session expires.
	ExpiresAt time.Time

	// T holds additional session data.
	//
	// Make sure to
	T *T
}

// Authenticator authenticates the user.
type Authenticator[T any] interface {
	Issue(http.ResponseWriter, *http.Request, *shield.User[T]) (*Session[T], error)
	Authenticate(http.ResponseWriter, *http.Request) (*Session[T], error)
}
