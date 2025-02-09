package token

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/uuidv7"
	"go.inout.gg/shield/shieldstrategy"
	"go.inout.gg/shield/shieldtoken"
)

var _ shieldstrategy.Authenticator[any] = (*tokenStrategy[any])(nil)

var ErrInvalidToken = errors.New("shield/token: invalid token")

var (
	DefaultAccessTokenExpiresIn  = time.Minute * 15
	DefaultRefreshTokenExpiresIn = time.Hour * 24 * 30
)

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
	// If token is not refreshable, this field can be empty.
	RefreshToken string
}

type Issuer[T any] interface {
	Issue(ctx context.Context, user *shield.User[T]) (*Token, error)
}

type tokenStrategy[T any] struct {
	storage Storage[T]
	issuer  Issuer[T]
	config  *Config
}

type Config struct {
	AccessTokenExpiresIn  time.Duration
	RefreshTokenExpiresIn time.Duration
}

func NewConfig(opts ...func(*Config)) *Config {
	c := &Config{}
	for _, opt := range opts {
		opt(c)
	}

	debug.Assert(c.AccessTokenExpiresIn > 0, "access token expiration must be greater than 0")
	debug.Assert(c.RefreshTokenExpiresIn > 0, "refresh token expiration must be greater than 0")

	return c
}

func (c *Config) defaults() {
	c.AccessTokenExpiresIn = cmp.Or(c.AccessTokenExpiresIn, DefaultAccessTokenExpiresIn)
	c.RefreshTokenExpiresIn = cmp.Or(c.RefreshTokenExpiresIn, DefaultRefreshTokenExpiresIn)
}

// New returns a new authenticator that authenticates using a bearer token.
func New[T any](storage Storage[T], issuer Issuer[T], config *Config) shieldstrategy.Authenticator[T] {
	return &tokenStrategy[T]{storage, issuer, config}
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

func (s *tokenStrategy[T]) Issue(
	w http.ResponseWriter,
	r *http.Request,
	user *shield.User[T],
) (*shieldstrategy.Session[T], error) {
	ctx := r.Context()
	_, err := s.issuer.Issue(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("shield/token: failed to issue token: %w", err)
	}

	return &shieldstrategy.Session[T]{
		ID:        uuidv7.Must(),
		ExpiresAt: time.Now().Add(s.config.AccessTokenExpiresIn),
		T:         nil,
	}, nil
}
