package driver

import (
	"context"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/shield/internal/dbsqlc"
)

type Querier interface {
	Queries() *dbsqlc.Queries
}

type ExecutorTx interface {
	Queries() *dbsqlc.Queries
	Tx() pgx.Tx
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

type Driver interface {
	Begin(context.Context) (ExecutorTx, error)
	Querier
}
