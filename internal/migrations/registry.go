package migrations

import (
	"embed"

	"go.inout.gg/conduit/conduitregistry"
)

var Registry = conduitregistry.New("inout/shield")

//go:embed **.sql
var migrationFS embed.FS

func init() {
	Registry.FromFS(migrationFS)
}
