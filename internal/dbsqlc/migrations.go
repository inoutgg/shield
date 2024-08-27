package dbsqlc

import "embed"

//go:embed *.sql
var MigrationFS embed.FS
