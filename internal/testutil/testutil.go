package testutil

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/foundations/sqldb/sqldbtest"

	"go.inout.gg/shield/shieldmigrate"
)

//nolint:gochecknoglobals
var migrator = shieldmigrate.New()

// MustDB creates a new testing db connection pool.
func MustDB(t *testing.T) *sqldbtest.DB {
	t.Helper()

	return sqldbtest.Must(
		t.Context(),
		t,
		sqldbtest.WithUp(
			func(ctx context.Context, conn *pgx.Conn) error {
				return migrator.Up(ctx, conn, nil)
			},
		),
	)
}
