package shieldmigrate

import (
	"context"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/conduit"
	"go.inout.gg/shield/internal/migrations"
)

// Migrator is a database migration utility to roll up and down shield's
// migrations in order.
type Migrator struct {
	base *conduit.Migrator
}

// MigrateOptions specifies options for migration operation.
type MigrateOptions struct {
	Steps int
}

// toConduit converts these options to a conduit migration options.
func (opts *MigrateOptions) toConduit() *conduit.MigrateOptions {
	return &conduit.MigrateOptions{
		Steps: opts.Steps,
	}
}

// New creates a new conduit migrator.
func New() *Migrator {
	base := conduit.NewMigrator(conduit.NewConfig(func(c *conduit.Config) {
		c.Registry = migrations.Registry
	}))

	return &Migrator{base}
}

func (m *Migrator) Up(ctx context.Context, conn *pgx.Conn, opts *MigrateOptions) error {
	var migrateOpts *conduit.MigrateOptions
	if opts != nil {
		migrateOpts = opts.toConduit()
	}

	_, err := m.base.Migrate(ctx, conduit.DirectionUp, conn, migrateOpts)
	return err
}

func (m *Migrator) Down(ctx context.Context, conn *pgx.Conn, opts *MigrateOptions) error {
	var migrateOpts *conduit.MigrateOptions
	if opts != nil {
		migrateOpts = opts.toConduit()
	}

	_, err := m.base.Migrate(ctx, conduit.DirectionDown, conn, migrateOpts)
	return err
}
