{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:
{
  packages = [
    pkgs.git
    pkgs.codex
    pkgs.ruff
  ];

  # https://devenv.sh/languages/
  languages.python = {
    enable = true;
    lsp.package = pkgs.ty;
    uv = {
      enable = true;
      sync.enable = true;
    };
    venv.enable = true;
  };

  treefmt = {
    enable = true;
    config.programs = {
      nixfmt.enable = true;
      ruff-check.enable = true;
    };
  };

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    treefmt.enable = true;
  };
}
