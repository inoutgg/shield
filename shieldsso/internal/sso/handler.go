// SSO implements authentication logic to sign in with OpenID providers.
package sso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"go.inout.gg/foundations/must"
	"golang.org/x/oauth2"

	"go.inout.gg/shield/internal/random"
)

type UserInfo[T any] interface {
	Claims() T
	Email() string
}

type Provider[T any] interface {
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	UserInfo(ctx context.Context, token *oauth2.Token) (UserInfo[T], error)
	AuthCodeURL(state string) string
}

type ProviderInfo[T any] struct {
	UserInfo UserInfo[T]

	RefreshToken string
	AccessToken  string
	Code         string
}

type ProviderState struct {
	State string
	Nonce string
	URL   string
}

// HandleAuthorize handles the authorization request to the OpenID provider.
func HandleAuthorize[T any](
	_ context.Context,
	_ *http.Request,
	provider Provider[T],
) (*ProviderState, error) {
	state := must.Must(random.SecureHexString(32))
	nonce := must.Must(random.SecureHexString(32))
	url := provider.AuthCodeURL(state)

	return &ProviderState{
		State: state,
		Nonce: nonce,
		URL:   url,
	}, nil
}

// HandleCallback handles the callback from the OpenID provider.
func HandleCallback[T any](
	ctx context.Context,
	r *http.Request,
	provider Provider[T],
) (*ProviderInfo[T], error) {
	query := parseQuery(r)

	extError := query.Get("error")
	if extError != "" {
		return nil, fmt.Errorf(
			"shield/sso: external error: %s",
			extError,
		)
	}

	code := query.Get("code")
	if code == "" {
		return nil, errors.New(
			"shield/sso: missing authentication code",
		)
	}

	token, err := provider.ExchangeCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf(
			"shield/sso: unable to exchange code for token: %w",
			err,
		)
	}

	userInfo, err := provider.UserInfo(ctx, token)
	if err != nil {
		return nil, fmt.Errorf(
			"shield/sso: unable to get user info: %w",
			err,
		)
	}

	return &ProviderInfo[T]{
		UserInfo:     userInfo,
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
		Code:         code,
	}, nil
}

// parseQuery parses the query parameters from the request.
//
// If the request method is GET, the query parameters are parsed from the URL,
// otherwise they are parsed from the request body with a fallback to the URL.
func parseQuery(req *http.Request) url.Values {
	if req.Method == http.MethodGet {
		return req.URL.Query()
	}

	if err := req.ParseForm(); err == nil {
		return req.Form
	}

	return req.URL.Query()
}
