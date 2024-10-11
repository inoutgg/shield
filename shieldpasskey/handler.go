package shieldpasskey

import (
	"context"
	"fmt"

	"go.inout.gg/shield/db/driver"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Handler struct {
	wa     *webauthn.WebAuthn
	driver driver.Driver
}

type Config struct {
	WebauthnConfig *webauthn.Config
}

func NewHandler(config *Config) (*Handler, error) {
	webauthn, err := webauthn.New(config.WebauthnConfig)
	if err != nil {
		return nil, fmt.Errorf("shield/passkey: unable to initialize handler: %w", err)
	}

	return &Handler{
		wa:     webauthn,
		driver: nil,
	}, nil
}

func (h *Handler) HandleStartUserLogin(ctx context.Context, email string) error {
	row, err := h.driver.Queries().FindUserWithPasskeyCredentialByEmail(ctx, email)
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
