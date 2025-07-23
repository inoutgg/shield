// Package union provides an authneticator that sequentially tries to authenticate
// user session with provided authenticators.
package union

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"go.inout.gg/shield"
	"go.inout.gg/shield/shieldsession"
)

var _ shieldsession.Authenticator[any, any] = (unionStrategy[any, any])(nil)

type unionStrategy[U any, S any] []shieldsession.Authenticator[U, S]

// New creates a new Authenticator that tries to authenticate session
// with provided authenticators.
//
// NOTE: the returned authneticator is not capable of issuing a new session.
func New[U any, S any](
	authenticators ...shieldsession.Authenticator[U, S],
) shieldsession.Authenticator[U, S] {
	return unionStrategy[U, S](authenticators)
}

// Authenticate tries to authenticate user session with provided authenticators.
//
// If all authenticators fail, the error is returned.
func (u unionStrategy[U, S]) Authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (shieldsession.Session[S], error) {
	var sess shieldsession.Session[S]

	errs := make([]error, 0)

	for _, authenticator := range u {
		sess, err := authenticator.Authenticate(w, r)
		if err != nil {
			errs = append(errs, err)
		} else {
			return sess, nil
		}
	}

	return sess, errors.Join(errs...)
}

// Issue is not supported by the union strategy.
func (unionStrategy[U, S]) Issue(
	http.ResponseWriter,
	*http.Request,
	shield.User[U],
) (shieldsession.Session[S], error) {
	var sess shieldsession.Session[S]

	return sess, errors.ErrUnsupported
}

func (unionStrategy[U, S]) ExpireSessions(context.Context, pgx.Tx) error {
	return errors.ErrUnsupported
}
