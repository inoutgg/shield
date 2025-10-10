cpus := shell('nproc --all')

setup:
    lefthook install -f

mod:
    go mod tidy
    go mod download
    gomod2nix

format:
    nix fmt

lint-fix:
  golangci-lint run --fix ./...

gen: mod
  go generate ./...

test-all:
  go test -race -count=1 -parallel=$(cpus) ./...
