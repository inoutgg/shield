package migrations

import (
	"embed"

	"go.inout.gg/conduit/conduitregistry"
)

var Registry = conduitregistry.New("inout/shield") //nolint:gochecknoglobals

//go:embed **.sql
var migrationFS embed.FS

//nolint:gochecknoinits
func init() {
	Registry.FromFS(migrationFS)
}
