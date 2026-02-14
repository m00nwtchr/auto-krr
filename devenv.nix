{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:
{
  packages =
    with pkgs;
    [
      git
      config.outputs.auto-krr
    ]
    ++ lib.optionals (!config.container.isBuilding) [
      ruff
      codex
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
      yamlfmt.enable = true;
    };
  };

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    treefmt.enable = true;
  };

  containers."auto-krr" = {
    entrypoint = [ "${config.outputs.auto-krr}/bin/auto-krr" ];
  };

  outputs = {
    auto-krr = config.languages.python.import ./. { };
  };
}
