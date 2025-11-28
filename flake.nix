{
  description = "Shield is a comprehensive, opinionated authentication framework for Go built on PostgreSQL";

  inputs = {
    devenv.url = "github:cachix/devenv";
    nixpkgs.url = "nixpkgs/nixos-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-root.url = "github:srid/flake-root";
    git-hooks-nix.url = "github:cachix/git-hooks.nix";
  };

  outputs =
    {
      flake-parts,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      flake = { };

      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      imports = [
        inputs.flake-root.flakeModule
        inputs.devenv.flakeModule
        inputs.git-hooks-nix.flakeModule
        inputs.treefmt-nix.flakeModule
      ];

      perSystem =
        {
          pkgs,
          lib,
          config,
          ...
        }:
        {
          formatter = config.treefmt.build.wrapper;

          treefmt.config = {
            inherit (config.flake-root) projectRootFile;
            package = pkgs.treefmt;

            programs = {
              nixfmt.enable = true;
              gofumpt = {
                enable = true;
                excludes = [
                  "*_mock.go"
                  "internal/dbsqlc/**"
                  "internal/dbsqlctest/**"
                ];
              };
              typos.enable = true;
            };
          };

          devenv.shells.default = {
            containers = lib.mkForce { };

            git-hooks = {
              hooks = {
                gen = {
                  enable = true;
                  name = "gen";
                  description = "Code generation";
                  entry = "${lib.getExe pkgs.just} gen";
                  pass_filenames = false;
                  files = "\\.(go|mod)$";
                };

                lint = {
                  after = [ "gen" ];
                  enable = true;
                  name = "lint";
                  description = "Lint checks";
                  entry = "${lib.getExe pkgs.just} lint";
                  pass_filenames = false;
                };
              };
            };

            packages = with pkgs; [
              golangci-lint
              govulncheck
              gotools
              mockgen

              sqlc
              just
            ];

            env.GOTOOLCHAIN = "local";
            env.GOFUMPT_SPLIT_LONG_LINES = "on";

            languages.go = {
              enable = true;
              package = pkgs.go_1_25;
            };
            languages.javascript = {
              enable = true;
              npm.enable = true;
            };

            services.postgres = {
              enable = true;
              package = pkgs.postgresql_17;
              initialScript = ''
                CREATE USER test SUPERUSER PASSWORD 'test';
                CREATE DATABASE test OWNER test;
              '';
              listen_addresses = "localhost";
              port = 5432;
            };
          };
        };
    };
}
