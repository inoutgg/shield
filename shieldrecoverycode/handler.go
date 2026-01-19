package shieldrecoverycode

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/foundations/debug"

	"go.inout.gg/shield"
	"go.inout.gg/shield/internal/dbsqlc"
	"go.inout.gg/shield/internal/random"
	"go.inout.gg/shield/shieldpassword"
)

var _ Generator = (*generator)(nil)

const (
	DefaultRecoveryCodeTotalCount = 16
	DefaultRecoveryCodeLength     = 16
)

//nolint:gochecknoglobals
var DefaultGenerator Generator = &generator{}

// Generator provides methods to create a set of unique recovery codes used
// for 2FA authentication recovery.
type Generator interface {
	Generate(cnt, l int) ([]string, error)
}

type generator struct{}

// Generate creates count number of secure random recovery codes.
// Each code is length bytes long and encoded as a hex string.
func (g *generator) Generate(count, length int) ([]string, error) {
	codes := make([]string, count)

	for i := range count {
		code, err := random.SecureHexString(length)
		if err != nil {
			return nil, fmt.Errorf(
				"shieldrecoverycode: failed to generate recovery code: %w",
				err,
			)
		}

		codes[i] = code
	}

	return codes, nil
}

type Config struct {
	Logger                 *slog.Logger
	PasswordHasher         shieldpassword.PasswordHasher
	Generator              Generator
	RecoveryCodeTotalCount int
	RecoveryCodeLength     int
}

func NewConfig(opts ...func(*Config)) *Config {
	//nolint:exhaustruct
	cfg := &Config{}
	for _, opt := range opts {
		opt(cfg)
	}

	cfg.defaults()
	cfg.assert()

	return cfg
}

func (c *Config) defaults() {
	c.PasswordHasher = cmp.Or(
		c.PasswordHasher,
		shieldpassword.DefaultPasswordHasher,
	)
	c.RecoveryCodeTotalCount = cmp.Or(
		c.RecoveryCodeTotalCount,
		DefaultRecoveryCodeTotalCount,
	)
	c.RecoveryCodeLength = cmp.Or(
		c.RecoveryCodeLength,
		DefaultRecoveryCodeLength,
	)
	c.Generator = cmp.Or(c.Generator, DefaultGenerator)
}

func (c *Config) assert() {
	debug.Assert(c.Logger != nil, "expected Logger to be defined")
	debug.Assert(
		c.PasswordHasher != nil,
		"expected PasswordHasher to be defined",
	)
	debug.Assert(c.Generator != nil, "expected Generator to be defined")
}

type Handler struct {
	config *Config
	dbtx   shield.DBTX
}

func New(dbtx shield.DBTX, config *Config) *Handler {
	if config == nil {
		config = NewConfig()
	}

	h := Handler{config, dbtx}
	h.assert()

	return &h
}

func (h *Handler) Generate() ([]string, error) {
	codes, err := h.config.Generator.Generate(
		h.config.RecoveryCodeTotalCount,
		h.config.RecoveryCodeLength,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"shieldrecoverycode: failed to generate recovery codes: %w",
			err,
		)
	}

	hashedCodes := make([]string, len(codes))

	for i, code := range codes {
		hashedCode, err := h.config.PasswordHasher.Hash(code)
		if err != nil {
			return nil, fmt.Errorf(
				"shieldrecoverycode: failed to hash recovery code: %w",
				err,
			)
		}

		hashedCodes[i] = hashedCode
	}

	return hashedCodes, nil
}

// CreateRecoveryCodes generates a new set of recovery codes.
func (h *Handler) CreateRecoveryCodes(
	ctx context.Context,
	userID int64,
) error {
	codes, err := h.Generate()
	if err != nil {
		return err
	}

	tx, err := h.dbtx.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shieldrecoverycode: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if err := h.CreateRecoveryCodesInTx(ctx, userID, codes, tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shieldrecoverycode: failed to commit transaction: %w",
			err,
		)
	}

	return nil
}

// RecreateRecoveryCodes recreates a new set of recovery codes for the user.RecreateRecoveryCodes
//
// Previous recovery codes are evicted.
func (h *Handler) RecreateRecoveryCodes(
	ctx context.Context,
	userID int64,
	replacedBy *int64,
) error {
	codes, err := h.Generate()
	if err != nil {
		return err
	}

	tx, err := h.dbtx.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"shieldrecoverycode: failed to begin transaction: %w",
			err,
		)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if err := h.RecreateRecoveryCodesInTx(ctx, userID, replacedBy, codes, tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"shieldrecoverycode: failed to commit transaction: %w",
			err,
		)
	}

	return nil
}

func (h *Handler) RecreateRecoveryCodesInTx(
	ctx context.Context,
	userID int64,
	replacedBy *int64,
	codes []string,
	tx pgx.Tx,
) error {
	if err := h.EvictRecoveryCodesInTx(ctx, userID, replacedBy, tx); err != nil {
		return err
	}

	if err := h.CreateRecoveryCodesInTx(ctx, userID, codes, tx); err != nil {
		return err
	}

	return nil
}

func (h *Handler) EvictRecoveryCodesInTx(
	ctx context.Context,
	userID int64,
	evictedBy *int64,
	tx pgx.Tx,
) error {
	arg := dbsqlc.EvictUnconsumedRecoveryCodeBatchParams{
		UserID:    userID,
		EvictedBy: evictedBy,
	}
	if err := dbsqlc.New().EvictUnconsumedRecoveryCodeBatch(ctx, tx, arg); err != nil {
		return fmt.Errorf(
			"shieldrecoverycode: failed to evict recovery codes: %w",
			err,
		)
	}

	return nil
}

func (h *Handler) CreateRecoveryCodesInTx(
	ctx context.Context,
	userID int64,
	codes []string,
	tx pgx.Tx,
) error {
	rows := make([]dbsqlc.CreateRecoveryCodeBatchParams, len(codes))
	for i, code := range codes {
		rows[i] = dbsqlc.CreateRecoveryCodeBatchParams{
			IsConsumable:     true,
			RecoveryCodeHash: code,
			UserID:           userID,
		}
	}

	if _, err := dbsqlc.New().CreateRecoveryCodeBatch(ctx, tx, rows); err != nil {
		return fmt.Errorf(
			"shieldrecoverycode: failed to create recovery codes: %w",
			err,
		)
	}

	return nil
}

func (h *Handler) assert() {
	h.config.assert()
	debug.Assert(h.dbtx != nil, "expected dbtx to be defined")
}
