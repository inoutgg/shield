package shieldmigrate

import (
	"context"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/conduit"
	"go.inout.gg/shield/internal/migrations"
)

type Migrator struct {
	base conduit.Migrator
}

func New() *Migrator {
	base := conduit.NewMigrator(conduit.NewConfig(func(c *conduit.Config) {
		c.Registry = migrations.Registry
	}))

	return &Migrator{base}
}

func (m *Migrator) Up(ctx context.Context, conn *pgx.Conn) error {
	_, err := m.base.Migrate(ctx, conduit.DirectionUp, conn)
	return err
}

func (m *Migrator) Down(ctx context.Context, conn *pgx.Conn) error {
	_, err := m.base.Migrate(ctx, conduit.DirectionDown, conn)
	return err
}
