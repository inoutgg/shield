{
  description = "Shield is a comprehensive, opinionated authentication framework for Go built on PostgreSQL";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Runtimes
            nodejs
            go_1_25

            # Tooling
            sqlc
            golangci-lint
            just
            typos
            lefthook

            mockgen

            # LSP
            golangci-lint-langserver
          ];
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
