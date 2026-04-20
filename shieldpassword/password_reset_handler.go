package shieldpassword

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/must"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/random"
	"go.inout.gg/shield/shieldsender"
)

// ErrUsedPasswordResetToken is returned when the password reset token has already been used.
var ErrUsedPasswordResetToken = errors.New(
	"shieldpasswordreset: password reset token has been used",
)

const (
	DefaultResetTokenExpiry = 15 * time.Minute
	DefaultResetTokenLength = 32
)

// PasswordResetConfig is the configuration for the PasswordResetHandler.
//
// Make sure to use the NewConfig function to create a new config, instead
// of instantiating the struct directly.
type PasswordResetConfig struct {
	PasswordHasher PasswordHasher // optional
	Logger         *slog.Logger   // optional

	// TokenLength set the length of the reset token.
	//
	// Defaults to DefaultResetTokenLength
	TokenLength int // optional

	// TokenExpiryIn set the expiry time of the reset token.
	//
	// Defaults to DefaultResetTokenExpiry
	TokenExpiryIn time.Duration // optional
}

// NewPasswordResetConfig creates a new config.
func NewPasswordResetConfig(opts ...func(*PasswordResetConfig)) *PasswordResetConfig {
	//nolint:exhaustruct
	config := &PasswordResetConfig{
		TokenExpiryIn: DefaultResetTokenExpiry,
		TokenLength:   DefaultResetTokenLength,
	}
	for _, opt := range opts {
		opt(config)
	}

	config.defaults()
	config.assert()

	return config
}

func (c *PasswordResetConfig) defaults() {
	c.TokenExpiryIn = cmp.Or(c.TokenExpiryIn, DefaultResetTokenExpiry)
	c.TokenLength = cmp.Or(c.TokenLength, DefaultResetTokenLength)
	c.PasswordHasher = cmp.Or(
		c.PasswordHasher,
		DefaultPasswordHasher,
	)
}

func (c *PasswordResetConfig) assert() {
	debug.Assert(c.PasswordHasher != nil, "PasswordHasher must be set")
}

// PasswordResetRequestMessagePayload is the payload for the reset token message.
type PasswordResetRequestMessagePayload struct {
	Token string
}

// PasswordResetHandler handles password reset requests.
//
// It is a general enough implementation so it can be used for different
// communication methods.
//
// Check out the FormHandler for a ready to use implementation that handles
// HTTP form requests.
type PasswordResetHandler[S any] struct {
	dbtx   shield.DBTX
	sender shieldsender.Sender
	config *PasswordResetConfig
}

func NewPasswordResetHandler[S any](
	dbtx shield.DBTX,
	sender shieldsender.Sender,
	config *PasswordResetConfig,
) *PasswordResetHandler[S] {
	if config == nil {
		config = NewPasswordResetConfig()
	}

	config.assert()

	h := PasswordResetHandler[S]{dbtx, sender, config}
	h.assert()

	return &h
}

// HandlePasswordReset handles a password reset request.
//
// SECURITY: this function doesn't check if the user is authenticated,
// user authentication should be verified before calling this function,
// and if the user is authenticated, prevent the user from resetting their password
// via this API.
func (h *PasswordResetHandler[S]) HandlePasswordReset(
	ctx context.Context,
	email string,
) error {
	user, err := dbsqlc.New().FindUserByEmail(ctx, h.dbtx, email)
	if err != nil {
		d("cannot reset password since user (%s) is not found: %v", email, err)

		return nil
	}

	tok, err := dbsqlc.New().
		UpsertPasswordResetToken(ctx, h.dbtx, dbsqlc.UpsertPasswordResetTokenParams{
			Token:     must.Must(random.SecureHexString(h.config.TokenLength)),
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(h.config.TokenExpiryIn),
		})
	if err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to upsert password reset token: %w",
			err,
		)
	}

	if err := h.sender.Send(ctx, shieldsender.Message{
		Email: user.Email,
		Key:   shieldsender.MessageKeyPasswordResetRequest,
		Payload: PasswordResetRequestMessagePayload{
			Token: tok.Token,
		},
	}); err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to send password reset token: %w",
			err,
		)
	}

	return nil
}

func (h *PasswordResetHandler[_]) HandlePasswordResetConfirm(
	ctx context.Context,
	password, tokStr string,
) error {
	// Hash password before tx to avoid unnecessary database delay.
	passwordHash, err := h.config.PasswordHasher.Hash(password)
	if err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to hash password: %w",
			err,
		)
	}

	tok, err := dbsqlc.New().FindPasswordResetToken(ctx, h.dbtx, tokStr)
	if err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to find password reset token: %w",
			err,
		)
	}

	if tok.IsUsed {
		return ErrUsedPasswordResetToken
	}

	user, err := dbsqlc.New().FindUserByID(ctx, h.dbtx, tok.UserID)
	if err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to find user: %w",
			err,
		)
	}

	tx, err := h.dbtx.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if err := dbsqlc.New().MarkPasswordResetTokenAsUsed(ctx, tx, tok.Token); err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to mark password reset token as used: %w",
			err,
		)
	}

	if err := dbsqlc.New().
		UpsertPasswordCredentialByUserID(ctx, tx, dbsqlc.UpsertPasswordCredentialByUserIDParams{
			UserID:               tok.UserID,
			UserCredentialKey:    user.Email,
			UserCredentialSecret: passwordHash,
		}); err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to set user password: %w",
			err,
		)
	}

	// Once password is changed, we need to expire all sessions for this user.
	//
	// TODO: we have to receive session manager as a parameter, since
	// there might be an external implementation of the session provider.
	if _, err := dbsqlc.New().
		ExpireAllSessionsByUserID(ctx, tx, dbsqlc.ExpireAllSessionsByUserIDParams{
			UserID:    user.ID,
			EvictedBy: &user.ID,
		}); err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to expire sessions: %w",
			err,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to commit transaction: %w",
			err,
		)
	}

	if err := h.sender.Send(ctx, shieldsender.Message{
		Email:   user.Email,
		Key:     shieldsender.MessageKeyPasswordResetSuccess,
		Payload: nil,
	}); err != nil {
		return fmt.Errorf(
			"shieldpasswordreset: failed to send success message: %w",
			err,
		)
	}

	return nil
}

func (h *PasswordResetHandler[_]) assert() {
	debug.Assert(h.dbtx != nil, "dbtx must be set")
	debug.Assert(h.sender != nil, "sender must be set")
}
