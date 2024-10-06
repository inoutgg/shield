// Package union provides an authneticator that sequencially tries to authenticate
// user session with provided authenticators.
package union

import (
	"errors"
	"net/http"

	"go.inout.gg/shield"
	"go.inout.gg/shield/shieldstrategy"
)

var _ shieldstrategy.Authenticator[any] = (unionStrategy[any])(nil)

type unionStrategy[T any] []shieldstrategy.Authenticator[T]

// New creates a new Authenticator that tries to authenticate session
// with provided authenticators.
//
// NOTE: the returned authneticator is not capable of issuing a new session.
func New[T any](authenticators ...shieldstrategy.Authenticator[T]) shieldstrategy.Authenticator[T] {
	return unionStrategy[T](authenticators)
}

func (u unionStrategy[T]) Authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (*shieldstrategy.Session[T], error) {
	errs := make([]error, 0)

	for _, authenticator := range u {
		user, err := authenticator.Authenticate(w, r)
		if err != nil {
			errs = append(errs, err)
		} else {
			return user, nil
		}
	}

	return nil, errors.Join(errs...)
}

func (_ unionStrategy[T]) Issue(
	http.ResponseWriter,
	*http.Request,
	*shield.User[T],
) (*shieldstrategy.Session[T], error) {
	return nil, errors.ErrUnsupported
}
