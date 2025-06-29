package migrations

import (
	"context"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/conduit/conduitmigrate"
)

//nolint:exhaustruct
var m20250629163154 = conduitmigrate.New(&conduitmigrate.Config{}) //nolint:gochecknoglobals

//nolint:gochecknoinits
func init() {
	Registry.Up(up20250629163154)
	Registry.Down(down20250629163154)
}

func up20250629163154(ctx context.Context, conn *pgx.Conn) error {
	//nolint:wrapcheck
	return m20250629163154.Up(ctx, conn)
}

func down20250629163154(ctx context.Context, conn *pgx.Conn) error {
	//nolint:wrapcheck
	return m20250629163154.Down(ctx, conn)
}
