package google

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"go.inout.gg/shield/shieldsso/internal/sso"
)

var _ sso.Provider[any] = (*provider[any])(nil)

const Issuer = "https://accounts.google.com"

const (
	AuthorizePath = "/sso/google"
	RedirectPath  = "/sso/google/callback"
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
func NewProvider[T any](
	ctx context.Context,
	cfg *Config,
) (sso.Provider[T], error) {
	oidcProvider, err := oidc.NewProvider(ctx, Issuer)
	if err != nil {
		// TODO(roman@vanesyan.com): fix it
		//nolint:wrapcheck
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

func (p *provider[T]) UserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (sso.UserInfo[T], error) {
	// TODO(roman@vanesyan.com): use userInfo.
	_, err := p.provider.UserInfo(ctx, p.config.TokenSource(ctx, token))
	if err != nil {
		return nil, fmt.Errorf(
			"shield/sso: unable to fetch user info for google account: %w",
			err,
		)
	}

	// TODO(roman@vanesyan.com): fix it
	//nolint:nilnil
	return nil, nil
}

func (p *provider[T]) ExchangeCode(
	ctx context.Context,
	code string,
) (*oauth2.Token, error) {
	// TODO(roman@vanesyan.com): fix it
	//nolint:wrapcheck
	return p.config.Exchange(ctx, code)
}

func (p *provider[T]) AuthCodeURL(state string) string {
	return p.config.AuthCodeURL(state)
}
