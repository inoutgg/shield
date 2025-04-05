package migrations

import (
	"context"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"go.inout.gg/conduit/conduitmigrate"
)

var (
	//nolint:gochecknoglobals,exhaustruct
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	//nolint:gochecknoglobals
	m1726951089532 = conduitmigrate.New(&conduitmigrate.Config{
		Logger: logger,
	})
)

//nolint:gochecknoinits
func init() {
	Registry.Up(up1726951089532)
	Registry.Down(down1726951089532)
}

func up1726951089532(ctx context.Context, conn *pgx.Conn) error {
	//nolint:wrapcheck
	return m1726951089532.Up(ctx, conn)
}

func down1726951089532(ctx context.Context, conn *pgx.Conn) error {
	//nolint:wrapcheck
	return m1726951089532.Down(ctx, conn)
}
