package shield

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	CredentialPassword   = "password"
	CredentialPasskey    = "passkey"
	CredentialSsoTwitter = "sso_twitter"
	CredentialSsoGoogle  = "sso_google"
)

const (
	MFAPasskey = "mfa_passkey"
	MFAEmail   = "mfa_email"
	MFAOTP     = "mfa_otp"
)

var (
	ErrAuthenticatedUser   = errors.New("shield: authenticated user access")
	ErrMFARequired         = errors.New("shield: mfa required")
	ErrUnauthenticatedUser = errors.New(
		"shield: unauthenticated user access",
	)
	ErrUserNotFound = errors.New("shield: user not found")
)

// Querier is an interface for executing SQL queries.
type Querier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error)
}

// DBTX is an interface common to pgx.Tx, pgx.Conn and pgxpool.Pool.
type DBTX interface {
	Querier
	Begin(context.Context) (pgx.Tx, error)
}
