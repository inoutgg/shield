package token

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"go.inout.gg/shield"
	 "go.inout.gg/shield/shieldstrategy"
)

var _ shieldstrategy.Authenticator[any] = (*tokenStrategy[any])(nil)

var ErrInvalidToken = errors.New("shield/token: invalid token")

type Storage[T any] interface {
	Retrieve(context.Context, Token) (*shieldstrategy.Session[T], error)
}

// Token cares information about an access token.
type Token struct {
	// AccessToken is a token allowing to access the protected resource.
	//
	// It can be any kind of bearer token, i.e., a JWT, an opaque token, etc.
	AccessToken string

	// RefreshToken is a typically used to refresh the access token.
	//
	// If can be an empty string when there is no need to refresh a token.
	RefreshToken string
}

type Issuer[T any] interface {
	Issue(ctx context.Context, user *shieldstrategy.User[T]) (*Token, error)
}

type tokenStrategy[T any] struct {
	storage Storage[T]
	issuer  Issuer[T]
}

// New returns a new authenticator that authenticates using a bearer token.
func New[T any](storage Storage[T], issuer Issuer[T]) shieldstrategy.Authenticator[T] {
	return &tokenStrategy[T]{storage, issuer}
}

func (t *tokenStrategy[T]) Authenticate(
	w http.ResponseWriter,
	r *http.Request,
) (*shieldstrategy.Session[T], error) {
	ctx := r.Context()
	token, err := shieldtoken.FromRequest(r)
	if err != nil {
		return nil, err
	}

	user, err := t.storage.Retrieve(ctx, Token{AccessToken: token})
	if err != nil {
		return nil, fmt.Errorf("shield/token: failed to retrieve user: %w", err)
	}

	return user, nil
}

func (_ tokenStrategy[T]) Issue(
	http.ResponseWriter,
	*http.Request,
	*shield.User[T],
) (*shieldstrategy.Session[T], error) {
	return nil, errors.ErrUnsupported
}
