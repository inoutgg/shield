package dbsqlt

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/conduit"
	"go.segfaultmedaddy.com/pgxephemeraltest"

	"go.inout.gg/shield/internal/migrations"
)

var _ pgxephemeraltest.Migrator = (*migrator)(nil)

var m = newMigrator() //nolint:gochecknoglobals

// migrator applies migrations to a database. It is used by
// pgxephemeraltest during creation of a database template.
type migrator struct {
	m *conduit.Migrator
}

func newMigrator() *migrator {
	m := conduit.NewMigrator(
		conduit.NewConfig(func(c *conduit.Config) {
			c.Registry = migrations.Registry
		}),
	)

	return &migrator{m}
}

func (m *migrator) Migrate(ctx context.Context, conn *pgx.Conn) error {
	_, err := m.m.Migrate(ctx, conduit.DirectionUp, conn, nil)
	if err != nil {
		return fmt.Errorf("dbsqlt: failed to migrate: %w", err)
	}

	return nil
}

func (m *migrator) Hash() string { return "shield" }
