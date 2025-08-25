setup:
    lefthook install -f

mod:
    go mod download
    go mod tidy

lint-fix:
  typos -w
  golangci-lint run --fix ./...

format-sql:
  npx prettier -w **/*.sql

gen:
  go generate ./...

test-all:
  go test -race -count=1 -parallel=4 ./...
