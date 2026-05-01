// Package shieldunionsession provides an authneticator that sequentially tries to authenticate
// user session with provided authenticators.
package shieldunionsession

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"go.inout.gg/shield"
	"go.inout.gg/shield/shielduser"
)

var _ shielduser.Authenticator[any, any] = (unionStrategy[any, any])(nil)

type unionStrategy[U any, S any] []shielduser.Authenticator[U, S]

// New creates a new Authenticator that tries to authenticate session
// with provided authenticators.
//
// NOTE: the returned authneticator is not capable of issuing a new session.
func New[U any, S any](
	authenticators ...shielduser.Authenticator[U, S],
) shielduser.Authenticator[U, S] {
	return unionStrategy[U, S](authenticators)
}

// Authenticate tries to authenticate user session with provided authenticators.
//
// If all authenticators fail, the error is returned.
func (u unionStrategy[U, S]) Authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (*shielduser.Session[S], error) {
	errs := make([]error, 0)

	for _, authenticator := range u {
		sess, err := authenticator.Authenticate(w, r)
		if err != nil {
			if errors.Is(err, shield.ErrMFARequired) {
				return sess, err
			}

			errs = append(errs, err)
		} else {
			return sess, nil
		}
	}

	return nil, errors.Join(errs...)
}

// Issue is not supported by the union strategy.
func (unionStrategy[U, S]) Issue(
	http.ResponseWriter,
	*http.Request,
	*shielduser.User[U],
) (*shielduser.Session[S], error) {
	return nil, errors.ErrUnsupported
}

func (unionStrategy[U, S]) ExpireSessions(context.Context, pgx.Tx) error {
	return errors.ErrUnsupported
}
