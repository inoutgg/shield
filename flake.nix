{
  description = "Shield is a comprehensive, opinionated authentication framework for Go built on PostgreSQL";

  inputs = {
    devenv.url = "github:cachix/devenv";
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-root.url = "github:srid/flake-root";
    git-hooks-nix.url = "github:cachix/git-hooks.nix";
    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      flake-parts,
      gomod2nix,
      devenv,
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
          self',
          inputs',
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
                  "*.sql.go"
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

                format = {
                  after = [ "gen" ];
                  enable = true;
                  name = "format";
                  description = "Code formatting";
                  entry = "${lib.getExe pkgs.just} format";
                  pass_filenames = false;
                };

                lint = {
                  after = [ "format" ];
                  enable = true;
                  name = "lint";
                  description = "Lint checks";
                  entry = "${lib.getExe pkgs.just} lint-fix";
                  pass_filenames = false;
                };
              };
            };

            packages = with pkgs; [
              gomod2nix.packages.${system}.default
              golangci-lint
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
              '';
              listen_addresses = "127.0.0.1";
              port = 6432;
              settings = {
                max_prepared_transactions = 262143;
              };
            };
          };
        };
    };
}
