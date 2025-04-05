package migrations

import (
	"embed"

	"go.inout.gg/conduit/conduitregistry"
)

//nolint:gochecknoglobals
var Registry = conduitregistry.New("inout/shield")

//go:embed **.sql
var migrationFS embed.FS

//nolint:gochecknoinits
func init() {
	Registry.FromFS(migrationFS)
}
