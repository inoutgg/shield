package github

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.inout.gg/shield/shieldsso"
	"golang.org/x/oauth2"
)

var _ shieldsso.Provider[any] = (*provider[any])(nil)

var Issuer = "https://token.actions.githubusercontent.com"

var (
	AuthorizePath = "/sso/github"
	RedirectPath  = "/sso/github/callback"
)

// Config holds the configuration for Google oauth2 shield.
type Config struct {
	ClientID     string
	ClientSecret string
	Domain       string
	Scopes       []string
}

type provider[T any] struct {
	config   oauth2.Config
	provider *oidc.Provider
}

// NewProvider creates a new OpenID OAuth2 provider.
func NewProvider[T any](ctx context.Context, cfg *Config) (shieldsso.Provider[T], error) {
	oidcProvider, err := oidc.NewProvider(ctx, Issuer)
	if err != nil {
		return nil, err
	}

	config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  cfg.Domain + RedirectPath,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	return &provider[T]{
		config:   config,
		provider: oidcProvider,
	}, nil
}

func (p *provider[T]) UserInfo(ctx context.Context, token *oauth2.Token) (shieldsso.UserInfo[T], error) {
	// TODO(roman@vanesyan.com): use userInfo.
	_, err := p.provider.UserInfo(ctx, p.config.TokenSource(ctx, token))
	if err != nil {
		return nil, fmt.Errorf(
			"shield/sso: unable to fetch user info for google account: %w",
			err,
		)
	}

	return nil, nil
}

func (p *provider[T]) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *provider[T]) AuthCodeURL(state string) string {
	return p.config.AuthCodeURL(state)
}
