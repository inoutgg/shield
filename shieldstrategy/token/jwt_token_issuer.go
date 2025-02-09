package token

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"go.inout.gg/shield"
)

var _ Issuer[any] = (*JWTTokenIssuer[any])(nil)

// JWTTokenIssuer issues JWT tokens.
type JWTTokenIssuer[T any] struct {
	config *JWTTokenIssuerConfig
}

type JWTTokenIssuerConfig struct {
	Signer         jwt.SigningMethod
	ClaimsProducer ClaimsProducer
}

func (c *JWTTokenIssuerConfig) defaults() {
	if c.Signer == nil {
		c.Signer = jwt.SigningMethodRS384
	}
}

type ClaimsProducer interface {
	AccessTokenClaims() jwt.Claims
	RefreshTokenClaims() jwt.Claims
}

// NewJWTTokenIssuer creates a new JWT token issuer.
func NewJWTTokenIssuer[T any](opts ...func(*JWTTokenIssuerConfig)) *JWTTokenIssuer[T] {
	config := &JWTTokenIssuerConfig{}
	for _, opt := range opts {
		opt(config)
	}

	config.defaults()

	return &JWTTokenIssuer[T]{config}
}

func (i *JWTTokenIssuer[T]) Issue(ctx context.Context, user *shield.User[T]) (*Token, error) {
	tok := jwt.NewWithClaims(i.config.Signer, jwt.MapClaims{}, nil)
	actok, err := tok.SigningString()
	if err != nil {
		return nil, fmt.Errorf("shieldstrategy/token: failed to create JWT token: %w", err)
	}

	return &Token{
		AccessToken: actok,
	}, nil
}
