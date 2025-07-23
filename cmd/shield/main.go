package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	dotenv "github.com/joho/godotenv"
	"go.inout.gg/conduit"
	"go.inout.gg/conduit/conduitcli"

	"go.inout.gg/shield/internal/migrations"
)

func main() {
	_ = dotenv.Load()

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
	)

	migrator := conduit.NewMigrator(
		conduit.NewConfig(func(c *conduit.Config) {
			c.Registry = migrations.Registry
		}),
	)

	if err := conduitcli.Execute(ctx, migrator); err != nil {
		cancel()
		log.Fatal(err)
	}

	cancel()
}
