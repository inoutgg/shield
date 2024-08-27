package driverpgxv5

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.inout.gg/shield/db/driver"
	"go.inout.gg/shield/internal/dbsqlc"
)

var _ driver.Driver = (*pgxDriver)(nil)
var _ driver.ExecutorTx = (*executorTx)(nil)

// pgxDriver is a pgx/v5 database driver for use with the authentication package.
type pgxDriver struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	queries *dbsqlc.Queries
}

// New returns a new pgx/v5 database driver for use with the authentication package.
//
// It takes a pgxpool.Pool for use with the driver. The pool should be open
// while the driver is in use.
func New(logger *slog.Logger, pool *pgxpool.Pool) *pgxDriver {
	return &pgxDriver{
		logger:  logger,
		pool:    pool,
		queries: dbsqlc.New(pool),
	}
}

func (d *pgxDriver) Queries() *dbsqlc.Queries { return d.queries }

func (d *pgxDriver) Begin(ctx context.Context) (driver.ExecutorTx, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/db: failed to begin transaction: %w", err)
	}

	return &executorTx{
		queries: d.queries.WithTx(tx),
		tx:      tx,
	}, nil
}

type executorTx struct {
	queries *dbsqlc.Queries
	tx      pgx.Tx
}

func (e *executorTx) Tx() pgx.Tx                         { return e.tx }
func (e *executorTx) Queries() *dbsqlc.Queries           { return e.queries }
func (e *executorTx) Commit(ctx context.Context) error   { return e.tx.Commit(ctx) }
func (e *executorTx) Rollback(ctx context.Context) error { return e.tx.Rollback(ctx) }
