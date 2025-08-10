package shieldpasswordreset

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/must"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/random"
	"go.inout.gg/shield/internal/tid"
	"go.inout.gg/shield/shieldpassword"
	"go.inout.gg/shield/shieldsender"
	"go.inout.gg/shield/shieldsession"
)

// ErrUsedPasswordResetToken is returned when the password reset token has already been used.
var ErrUsedPasswordResetToken = errors.New(
	"shield/passwordreset: used password reset token",
)

const (
	DefaultResetTokenExpiry = 12 * time.Hour
	DefaultResetTokenLength = 32
)

// Config is the configuration for the password handler.
//
// Make sure to use the NewConfig function to create a new config, instead
// of instantiating the struct directly.
type Config struct {
	PasswordHasher shieldpassword.PasswordHasher // optional
	Logger         *slog.Logger                  // optional

	// TokenLength set the length of the reset token.
	//
	// Defaults to DefaultResetTokenExpiry.
	TokenLength int // optional

	// TokenExpiryIn set the expiry time of the reset token.
	//
	// Defaults to DefaultResetTokenLength
	TokenExpiryIn time.Duration // optional
}

func (c *Config) defaults() {
	c.TokenExpiryIn = cmp.Or(c.TokenExpiryIn, DefaultResetTokenExpiry)
	c.TokenLength = cmp.Or(c.TokenLength, DefaultResetTokenLength)
	c.Logger = cmp.Or(c.Logger, shield.DefaultLogger)
	c.PasswordHasher = cmp.Or(
		c.PasswordHasher,
		shieldpassword.DefaultPasswordHasher,
	)
}

func (c *Config) assert() {
	debug.Assert(c.PasswordHasher != nil, "PasswordHasher must be set")
	debug.Assert(c.Logger != nil, "Logger must be set")
}

// NewConfig creates a new config.
func NewConfig(opts ...func(*Config)) *Config {
	//nolint:exhaustruct
	config := &Config{
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

// WithPasswordHasher configures the password hasher.
//
// When setting a password hasher make sure to set it across all modules,
// such as user registrration, password reset and password verification.
func WithPasswordHasher(hasher shieldpassword.PasswordHasher) func(*Config) {
	return func(cfg *Config) { cfg.PasswordHasher = hasher }
}

// ResetTokenMessagePayload is the payload for the reset token message.
type PasswordResetRequestMessagePayload struct {
	Token string
}

// Handler handles password reset requests.
//
// It is a general enough implementation so it can be used for different
// communication methods.
//
// Check out the FormHandler for a ready to use implementation that handles
// HTTP form requests.
type Handler struct {
	pool   *pgxpool.Pool
	sender shieldsender.Sender
	config *Config
}

func NewHandler(
	pool *pgxpool.Pool,
	sender shieldsender.Sender,
	config *Config,
) *Handler {
	if config == nil {
		config = NewConfig()
	}

	config.assert()

	h := Handler{pool, sender, config}
	h.assert()

	return &h
}

func (h *Handler) assert() {
	debug.Assert(h.pool != nil, "pool must be set")
	debug.Assert(h.sender != nil, "sender must be set")
}

// HandlePasswordReset handles a password reset request.
func (h *Handler) HandlePasswordReset(
	ctx context.Context,
	email string,
) error {
	// Forbid authorized user access.
	if shieldsession.IsAuthenticated(ctx) {
		return shield.ErrAuthenticatedUser
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	user, err := dbsqlc.New().FindUserByEmail(ctx, tx, email)
	if err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to find user: %w",
			err,
		)
	}

	tokStr := must.Must(random.SecureHexString(h.config.TokenLength))

	tok, err := dbsqlc.New().
		UpsertPasswordResetToken(ctx, tx, dbsqlc.UpsertPasswordResetTokenParams{
			ID:        tid.MustPasswordResetID(),
			Token:     tokStr,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(h.config.TokenExpiryIn),
		})
	if err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to upsert password reset token: %w",
			err,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to commit transaction: %w",
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
			"shield/passwordreset: failed to send password reset token: %w",
			err,
		)
	}

	return nil
}

func (h *Handler) HandlePasswordResetConfirm(
	ctx context.Context,
	password, tokStr string,
) error {
	// Hash password before tx to avoid unnecessary database delay.
	passwordHash, err := h.config.PasswordHasher.Hash(password)
	if err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to hash password: %w",
			err,
		)
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	tok, err := dbsqlc.New().FindPasswordResetToken(ctx, tx, tokStr)
	if err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to find password reset token: %w",
			err,
		)
	}

	if tok.IsUsed {
		return ErrUsedPasswordResetToken
	}

	user, err := dbsqlc.New().FindUserByID(ctx, tx, tok.UserID)
	if err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to find user: %w",
			err,
		)
	}

	if err := dbsqlc.New().MarkPasswordResetTokenAsUsed(ctx, tx, tok.Token); err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to mark password reset token as used: %w",
			err,
		)
	}

	if err := dbsqlc.New().UpsertPasswordCredentialByUserID(ctx, tx, dbsqlc.UpsertPasswordCredentialByUserIDParams{
		ID:                   tid.MustCredentialID(),
		UserID:               tok.UserID,
		UserCredentialKey:    user.Email,
		UserCredentialSecret: passwordHash,
	}); err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to set user password: %w",
			err,
		)
	}

	// Once password is changed, we need to expire all sessions for this user.
	if _, err := dbsqlc.New().ExpireAllSessionsByUserID(ctx, tx, dbsqlc.ExpireAllSessionsByUserIDParams{
		UserID:    user.ID,
		EvictedBy: &user.ID,
	}); err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to expire sessions: %w",
			err,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to commit transaction: %w",
			err,
		)
	}

	if err := h.sender.Send(ctx, shieldsender.Message{
		Email:   user.Email,
		Key:     shieldsender.MessageKeyPasswordResetSuccess,
		Payload: nil,
	}); err != nil {
		return fmt.Errorf(
			"shield/passwordreset: failed to send success message: %w",
			err,
		)
	}

	return nil
}
