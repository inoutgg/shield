package shieldpasskey

import (
	"context"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
)

type Handler struct {
	wa   *webauthn.WebAuthn
	dbtx shield.DBTX
}

type Config struct {
	WebauthnConfig *webauthn.Config
}

func NewHandler(dbtx shield.DBTX, config *Config) (*Handler, error) {
	wa, err := webauthn.New(config.WebauthnConfig)
	if err != nil {
		return nil, fmt.Errorf(
			"shieldpasskey: unable to initialize handler: %w",
			err,
		)
	}

	return &Handler{
		wa,
		dbtx,
	}, nil
}

func (h *Handler) HandleStartUserLogin(
	ctx context.Context,
	email string,
) error {
	row, err := dbsqlc.New().
		FindUserWithPasskeyCredentialByEmail(ctx, h.dbtx, email)
	if err != nil {
		return fmt.Errorf(
			"shieldpasskey: failed to retrieve a user: %w",
			err,
		)
	}

	user := &user{row}

	_, _, err = h.wa.BeginLogin(user, nil)
	if err != nil {
		return fmt.Errorf(
			"shieldpasskey: unable to initialize passkey login flow: %w",
			err,
		)
	}

	return nil
}

func (h *Handler) HandleEndUserLogin(_ context.Context) error {
	return nil
}
