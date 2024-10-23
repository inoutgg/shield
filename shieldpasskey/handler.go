package shieldpasskey

import (
	"context"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/shield/internal/dbsqlc"
)

type Handler struct {
	wa   *webauthn.WebAuthn
	pool *pgxpool.Pool
}

type Config struct {
	WebauthnConfig *webauthn.Config
}

func NewHandler(pool *pgxpool.Pool, config *Config) (*Handler, error) {
	wa, err := webauthn.New(config.WebauthnConfig)
	if err != nil {
		return nil, fmt.Errorf("shield/passkey: unable to initialize handler: %w", err)
	}

	return &Handler{
		wa,
		pool,
	}, nil
}

func (h *Handler) HandleStartUserLogin(ctx context.Context, email string) error {
	queries := dbsqlc.New()
	row, err := queries.FindUserWithPasskeyCredentialByEmail(ctx, h.pool, email)
	if err != nil {
		return fmt.Errorf("shield/passkey: failed to retrieve a user: %w", err)
	}

	user := &user{row}
	_, _, err = h.wa.BeginLogin(user, nil)
	if err != nil {
		return fmt.Errorf("shield/passkey: unable to initialize passkey login flow: %w", err)
	}

	return nil
}

func (h *Handler) HandleEndUserLogin(ctx context.Context) error {
	return nil
}
