package testutil

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/foundations/sqldb/sqldbtest"
	"go.inout.gg/shield/shieldmigrate"
)

var migrator = shieldmigrate.New()

// MustDB creates a new testing db connection pool.
func MustDB(ctx context.Context, t *testing.T) *sqldbtest.DB {
	return sqldbtest.Must(ctx, t, sqldbtest.WithUp(func(ctx context.Context, conn *pgx.Conn) error {
		return migrator.Up(ctx, conn, nil)
	}))
}
