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
	"go.inout.gg/foundations/pointer"
	"go.inout.gg/foundations/sqldb"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/uuidv7"
	"go.inout.gg/shield/shieldpasswordverifier"
	"go.inout.gg/shield/shieldsender"
	"go.inout.gg/shield/shieldsession"
)

var (
	ErrEmailAlreadyTaken = errors.New(
		"shield/password: email already taken",
	)
	ErrPasswordIncorrect = errors.New("shield/password: password incorrect")
)

// Config is the configuration for the password handler.
type Config[U any] struct {
	Logger           *slog.Logger
	PasswordHasher   PasswordHasher
	PasswordVerifier shieldpasswordverifier.PasswordVerifier
	Hooker           Hooker[U]
}

func (c *Config[U]) defaults() {
	c.Logger = cmp.Or(c.Logger, shield.DefaultLogger)
	c.PasswordHasher = cmp.Or(c.PasswordHasher, DefaultPasswordHasher)
}

func (c *Config[U]) assert() {
	debug.Assert(c.PasswordHasher != nil, "PasswordHasher must be set")
	debug.Assert(c.Logger != nil, "Logger must be set")
}

// Hooker allows to hook into the user registration and logging in sessions
// and perform additional operations.
type Hooker[U any] interface {
	// OnUserRegistration is called when registering a new user.
	// Use this method to create an additional context for the user.
	OnUserRegistration(context.Context, uuid.UUID, pgx.Tx) (U, error)

	// OnUserLogin is called when a user is trying to login.
	// Use this method to fetch additional data from the database for the user.
	//
	// Note that the user password is not verified at this moment yet.
	OnUserLogin(context.Context, uuid.UUID, pgx.Tx) (U, error)
}

// NewConfig creates a new config.
//
// If no password hasher is configured, the DefaultPasswordHasher will be used.
func NewConfig[U any](opts ...func(*Config[U])) *Config[U] {
	//nolint:exhaustruct
	config := Config[U]{}
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
func WithPasswordHasher[U any](hasher PasswordHasher) func(*Config[U]) {
	return func(cfg *Config[U]) { cfg.PasswordHasher = hasher }
}

func WithHooker[U any](hooker Hooker[U]) func(*Config[U]) {
	return func(cfg *Config[U]) { cfg.Hooker = hooker }
}

type Handler[U, S any] struct {
	pool          *pgxpool.Pool
	config        *Config[U]
	authenticator shieldsession.Authenticator[U, S]
	sender        shieldsender.Sender
}

// It provides functionality to.
func NewHandler[U, S any](
	pool *pgxpool.Pool,
	authenticator shieldsession.Authenticator[U, S],
	sender shieldsender.Sender,
	config *Config[U],
) *Handler[U, S] {
	if config == nil {
		config = NewConfig[U]()
	}

	config.assert()

	h := Handler[U, S]{
		pool:          pool,
		config:        config,
		authenticator: authenticator,
		sender:        sender,
	}

	debug.Assert(h.pool != nil, "Logger must be set")

	return &h
}

// HandleChangeUserPassword changes a user password to a provided newPassword, if
// the current set password matching oldPassword.
//
// The user ID is expected to be provide via a session assigned to a passed ctx context.
//
// If no password was previously set for a user a new credential will be created.
func (h *Handler[_, S]) HandleChangeUserPassword(
	ctx context.Context,
	oldPassword, newPassword string,
) error {
	sess, err := shieldsession.FromContext[S](ctx)
	if err != nil {
		return fmt.Errorf(
			"shield/password: failed to retrieve session from the context: %w",
			err,
		)
	}

	// Make sure that the password hashing is performed outside of the transaction
	// as it is an expensive operation.
	passwordHash, err := h.config.PasswordHasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf(
			"shield/password: failed to hash password: %w",
			err,
		)
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shield/password: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	dbUser, err := dbsqlc.New().
		FindUserWithPasswordCredentialByUserID(ctx, tx, sess.UserID)
	if err != nil {
		return fmt.Errorf(
			"shield/password: failed to retrieve users credentials: %w",
			err,
		)
	}

	if dbUser.PasswordHash == nil && oldPassword == "" {
		if err := dbsqlc.New().UpsertPasswordCredentialByUserID(ctx, tx, dbsqlc.UpsertPasswordCredentialByUserIDParams{
			ID:                   uuidv7.Must(uuidv7.PrefixCredential),
			UserID:               dbUser.ID,
			UserCredentialKey:    dbUser.Email,
			UserCredentialSecret: passwordHash,
		}); err != nil {
			return fmt.Errorf(
				"shield/password: failed to create user credential: %w",
				err,
			)
		}

		d(
			"created a new user password credential for the user with ID: %v",
			dbUser.ID,
		)
	} else {
		ok, err := h.config.PasswordHasher.Verify(pointer.ToValue(dbUser.PasswordHash, ""), oldPassword)
		if err != nil {
			return fmt.Errorf("shield/password: failed to verify password: %w", err)
		}

		if !ok {
			d("password mismatch")
			return ErrPasswordIncorrect
		}
	}

	err = h.authenticator.ExpireSessions(ctx, tx)
	if err != nil {
		if !errors.Is(err, errors.ErrUnsupported) {
			return fmt.Errorf(
				"shield/password: failed to expire sessions: %w",
				err,
			)
		}

		d(
			"session expiration feature is not supported by a given authenticator",
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shield/password: failed to register a user: %w",
			err,
		)
	}

	return nil
}

func (h *Handler[U, _]) HandleUserRegistration(
	ctx context.Context,
	email, password string,
) (shield.User[U], error) {
	var user shield.User[U]

	// Forbid authorized user access.
	if shieldsession.IsAuthenticated(ctx) {
		return user, shield.ErrAuthenticatedUser
	}

	// Make sure that the password hashing is performed outside of the transaction
	// as it is an expensive operation.
	passwordHash, err := h.config.PasswordHasher.Hash(password)
	if err != nil {
		return user, fmt.Errorf(
			"shield/password: failed to hash password: %w",
			err,
		)
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return user, fmt.Errorf(
			"shield/password: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	userID, err := h.handleUserRegistrationTx(ctx, email, passwordHash, tx)
	if err != nil {
		return user, err
	}

	// An entry point for hooking the user registration process.
	var payload U

	if h.config.Hooker != nil {
		d("registration hooking is enabled, trying to get payload")

		payload, err = h.config.Hooker.OnUserRegistration(
			ctx,
			userID,
			tx,
		)
		if err != nil {
			return user, fmt.Errorf(
				"shield/password: failed to hook user registration: %w",
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return user, fmt.Errorf(
			"shield/password: failed to register a user: %w",
			err,
		)
	}

	user.ID = userID
	user.T = &payload

	return user, nil
}

func (h *Handler[U, _]) handleUserRegistrationTx(
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

		return uid, fmt.Errorf(
			"shield/password: failed to register a user: %w",
			err,
		)
	}

	if err := dbsqlc.New().UpsertPasswordCredentialByUserID(ctx, tx, dbsqlc.UpsertPasswordCredentialByUserIDParams{
		ID:                   uuidv7.Must(),
		UserID:               uid,
		UserCredentialKey:    email,
		UserCredentialSecret: passwordHash,
	}); err != nil {
		return uid, fmt.Errorf(
			"shield/password: failed to register a user: %w",
			err,
		)
	}

	return uid, nil
}

func (h *Handler[U, _]) HandleUserLogin(
	ctx context.Context,
	email, password string,
) (shield.User[U], error) {
	var user shield.User[U]

	// Forbid authorized user access.
	if shieldsession.IsAuthenticated(ctx) {
		return user, shield.ErrAuthenticatedUser
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return user, fmt.Errorf(
			"shield/password: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	dbUser, err := dbsqlc.New().FindUserWithPasswordCredentialByEmail(
		ctx,
		tx,
		email,
	)
	if err != nil {
		if sqldb.IsNotFoundError(err) {
			return user, shield.ErrUserNotFound
		}

		return user, fmt.Errorf(
			"shield/password: failed to find user: %w",
			err,
		)
	}

	// Treat the empty password as a non-existing user/credential.
	if dbUser.PasswordHash == "" {
		d("empty password in db")
		return user, shield.ErrUserNotFound
	}

	// An entry point for hooking the user login process.
	var payload U

	if h.config.Hooker != nil {
		d("login hooking is enabled, trying to get payload")

		payload, err = h.config.Hooker.OnUserLogin(ctx, user.ID, tx)
		if err != nil {
			return user, fmt.Errorf(
				"shield/password: failed to hook user login: %w",
				err,
			)
		}
	}

	// Make sure that the password hashing is performed outside of the transaction.
	if err := tx.Commit(ctx); err != nil {
		return user, fmt.Errorf(
			"shield/password: failed to login a user: %w",
			err,
		)
	}

	ok, err := h.config.PasswordHasher.Verify(dbUser.PasswordHash, password)
	if err != nil {
		return user, fmt.Errorf(
			"shield/password: failed to verify password: %w",
			err,
		)
	}

	if !ok {
		d("password mismatch")
		return user, ErrPasswordIncorrect
	}

	user.ID = dbUser.ID
	user.T = &payload

	return user, nil
}
