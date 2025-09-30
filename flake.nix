{
  description = "Shield is a comprehensive, opinionated authentication framework for Go built on PostgreSQL";

  inputs = {
    devenv.url = "github:cachix/devenv";
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    flake-parts.url = "github:hercules-ci/flake-parts";
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
        inputs.devenv.flakeModule
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
            # inherit (config.flake-root) projectRootfile;
            package = pkgs.treefmt;

            programs = {
              nixfmt.enable = true;
              gofumpt.enable = true;
              # prettier.enable = true;
            };
          };

          devenv.shells.default = {
            containers = lib.mkForce { };

            packages = with pkgs; [
              pgbouncer
              gomod2nix.packages.${system}.default

              sqlc
              watchexec
              just
              lefthook
              typos
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
                CREATE USER postgres SUPERUSER PASSWORD 'postgres';
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
