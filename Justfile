export PARALLEL_CNT := $(nproc --all)

setup:
    lefthook install -f

mod:
    go mod tidy
    go mod download
    gomod2nix

lint-fix:
  typos -w
  golangci-lint run --fix ./...

format-sql:
  npx prettier -w **/*.sql

gen:
  go generate ./...

test-all:
  go test -race -count=1 -parallel=4 ./...
