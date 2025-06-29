package shieldpassword

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/foundations/debug"
	"go.inout.gg/foundations/sqldb"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/uuidv7"
	"go.inout.gg/shield/shieldpasswordverifier"
	"go.inout.gg/shield/shielduser"
)

var (
	ErrEmailAlreadyTaken = errors.New("shield/password: email already taken")
	ErrPasswordIncorrect = errors.New("shield/password: password incorrect")
)

// Config is the configuration for the password handler.
type Config[T any] struct {
	Logger           *slog.Logger
	PasswordHasher   PasswordHasher
	PasswordVerifier shieldpasswordverifier.PasswordVerifier
	Hooker           Hooker[T]
}

func (c *Config[T]) defaults() {
	c.Logger = cmp.Or(c.Logger, shield.DefaultLogger)
	c.PasswordHasher = cmp.Or(c.PasswordHasher, DefaultPasswordHasher)
}

func (c *Config[T]) assert() {
	debug.Assert(c.PasswordHasher != nil, "PasswordHasher must be set")
	debug.Assert(c.Logger != nil, "Logger must be set")
}

// Hooker allows to hook into the user registration and logging in sessions
// and perform additional operations.
type Hooker[T any] interface {
	// HookUserRegistration is called when registering a new user.
	// Use this method to create an additional context for the user.
	HookUserRegistration(context.Context, uuid.UUID, pgx.Tx) (T, error)

	// HookUserLogin is called when a user is trying to login.
	// Use this method to fetch additional data from the database for the user.
	//
	// Note that the user password is not verified at this moment yet.
	HookUserLogin(context.Context, uuid.UUID, pgx.Tx) (T, error)
}

// NewConfig creates a new config.
//
// If no password hasher is configured, the DefaultPasswordHasher will be used.
func NewConfig[T any](opts ...func(*Config[T])) *Config[T] {
	//nolint:exhaustruct
	config := Config[T]{}
	for _, opt := range opts {
		opt(&config)
	}

	config.defaults()
	config.assert()

	return &config
}

// WithPasswordHasher configures the password hasher.
//
// When setting a password hasher make sure to set it across all modules,
// i.e., user registration, password reset and password verification.
func WithPasswordHasher[T any](hasher PasswordHasher) func(*Config[T]) {
	return func(cfg *Config[T]) { cfg.PasswordHasher = hasher }
}

func WithHooker[T any](hooker Hooker[T]) func(*Config[T]) {
	return func(cfg *Config[T]) { cfg.Hooker = hooker }
}

type Handler[T any] struct {
	pool   *pgxpool.Pool
	config *Config[T]
}

func NewHandler[T any](pool *pgxpool.Pool, config *Config[T]) *Handler[T] {
	if config == nil {
		config = NewConfig[T]()
	}

	config.assert()

	h := Handler[T]{pool, config}
	h.assert()

	return &h
}

func (h *Handler[T]) assert() {
	debug.Assert(h.pool != nil, "Logger must be set")
}

func (h *Handler[T]) HandleUserRegistration(
	ctx context.Context,
	email, password string,
) (*shield.User[T], error) {
	// Forbid authorized user access.
	if shielduser.IsAuthenticated(ctx) {
		return nil, shield.ErrAuthenticatedUser
	}

	// Make sure that the password hashing is performed outside of the transaction
	// as it is an expensive operation.
	passwordHash, err := h.config.PasswordHasher.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("shield/password: failed to hash password: %w", err)
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/password: failed to begin transaction: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	uid, err := h.handleUserRegistrationTx(ctx, email, passwordHash, tx)
	if err != nil {
		return nil, err
	}

	// An entry point for hooking the user registration process.
	var payload T

	if h.config.Hooker != nil {
		d("registration hooking is enabled, trying to get payload")

		payload, err = h.config.Hooker.HookUserRegistration(ctx, uid, tx)
		if err != nil {
			return nil, fmt.Errorf(
				"shield/password: failed to hook user registration: %w",
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("shield/password: failed to register a user: %w", err)
	}

	return &shield.User[T]{
		ID: uid,
		T:  &payload,
	}, nil
}

func (h *Handler[T]) handleUserRegistrationTx(
	ctx context.Context,
	email, passwordHash string,
	tx pgx.Tx,
) (uuid.UUID, error) {
	uid := uuidv7.Must()

	if err := dbsqlc.New().CreateUser(ctx, tx, dbsqlc.CreateUserParams{
		ID:    uid,
		Email: email,
	}); err != nil {
		if sqldb.IsUniqueViolationError(err) {
			d("email already exists")
			return uid, ErrEmailAlreadyTaken
		}

		return uid, fmt.Errorf("shield/password: failed to register a user: %w", err)
	}

	if err := dbsqlc.New().CreateUserPasswordCredential(ctx, tx, dbsqlc.CreateUserPasswordCredentialParams{
		ID:                   uuidv7.Must(),
		UserID:               uid,
		UserCredentialKey:    email,
		UserCredentialSecret: passwordHash,
	}); err != nil {
		return uid, fmt.Errorf("shield/password: failed to register a user: %w", err)
	}

	return uid, nil
}

func (h *Handler[T]) HandleUserLogin(
	ctx context.Context,
	email, password string,
) (*shield.User[T], error) {
	// Forbid authorized user access.
	if shielduser.IsAuthenticated(ctx) {
		return nil, shield.ErrAuthenticatedUser
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/password: failed to begin transaction: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	user, err := dbsqlc.New().FindUserWithPasswordCredentialByEmail(
		ctx,
		tx,
		email,
	)
	if err != nil {
		if sqldb.IsNotFoundError(err) {
			return nil, shield.ErrUserNotFound
		}

		return nil, fmt.Errorf("shield/password: failed to find user: %w", err)
	}

	// Treat the empty password as a non-existing user/credential.
	if user.PasswordHash == "" {
		d("empty password in db")
		return nil, shield.ErrUserNotFound
	}

	// An entry point for hooking the user login process.
	var payload T

	if h.config.Hooker != nil {
		d("login hooking is enabled, trying to get payload")

		payload, err = h.config.Hooker.HookUserLogin(ctx, user.ID, tx)
		if err != nil {
			return nil, fmt.Errorf(
				"shield/password: failed to hook user login: %w",
				err,
			)
		}
	}

	// Make sure that the password hashing is performed outside of the transaction.
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("shield/password: failed to login a user: %w", err)
	}

	ok, err := h.config.PasswordHasher.Verify(user.PasswordHash, password)
	if err != nil {
		return nil, fmt.Errorf("shield/password: failed to verify password: %w", err)
	}

	if !ok {
		d("password mismatch")
		return nil, ErrPasswordIncorrect
	}

	return &shield.User[T]{
		ID: user.ID,
		T:  &payload,
	}, nil
}
