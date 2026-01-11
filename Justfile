cpus := shell('nproc --all')

mod:
    go mod tidy
    go mod download

fmt:
    nix fmt

lint:
    govulncheck ./...
    golangci-lint run ./...
    nix flake check --no-pure-eval .

lint-fix:
    modernize --fix ./...
    golangci-lint run --fix ./...

gen: mod
    go generate ./...

all: gen lint-fix fmt

test-all:
    go test -race -parallel=$(cpus) ./...
