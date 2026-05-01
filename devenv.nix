{ pkgs, lib, ... }:
{
  treefmt = {
    enable = true;
    config.programs = {
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

  git-hooks.hooks = {
    gen = {
      enable = true;
      name = "gen";
      description = "Code generation";
      entry = "${lib.getExe pkgs.devenv} tasks run shield:gen";
      pass_filenames = false;
      files = "\\.(go|mod)$";
    };

    lint = {
      after = [ "gen" ];
      enable = true;
      name = "lint";
      description = "Lint checks";
      entry = "${lib.getExe pkgs.devenv} tasks run shield:lint";
      pass_filenames = false;
    };
  };

  tasks = {
    "shield:mod" = {
      description = "Update Go module metadata";
      exec = ''
        go mod tidy
        go mod download
      '';
    };

    "shield:fmt" = {
      description = "Format repository files";
      exec = "treefmt";
    };

    "shield:lint" = {
      description = "Run lint checks";
      exec = ''
        govulncheck ./...
        golangci-lint run ./...
        treefmt --fail-on-change
      '';
    };

    "shield:lint-fix" = {
      description = "Apply automatic lint fixes";
      exec = ''
        modernize --fix ./...
        golangci-lint run --fix ./...
      '';
    };

    "shield:gen" = {
      description = "Run code generation";
      after = [ "shield:mod" ];
      exec = "go generate ./...";
    };

    "shield:all" = {
      description = "Run generation, lint fixes, and formatting";
      after = [
        "shield:gen"
        "shield:lint-fix"
        "shield:fmt"
      ];
      exec = "true";
    };

    "shield:test-all" = {
      description = "Run all Go tests with race detector";
      exec = ''
        cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
        go test -race -parallel="$cpus" ./...
      '';
    };
  };

  packages = with pkgs; [
    golangci-lint
    govulncheck
    gotools
    mockgen
    sqlc
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
}
