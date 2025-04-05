package shieldstrategy

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"go.inout.gg/shield"
)

type Session[T any] struct {
	ExpiresAt time.Time
	T         *T
	ID        uuid.UUID
}

// Authenticator authenticates the user.
type Authenticator[T any] interface {
	Issue(http.ResponseWriter, *http.Request, *shield.User[T]) (*Session[T], error)
	Authenticate(http.ResponseWriter, *http.Request) (*Session[T], error)
}
