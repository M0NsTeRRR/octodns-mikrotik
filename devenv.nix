{
  pkgs,
  lib,
  config,
  ...
}:
{
  env = {
    MIKROTIK_HOST = config.secretspec.secrets.MIKROTIK_HOST or "";
    MIKROTIK_USER = config.secretspec.secrets.MIKROTIK_USER or "";
    MIKROTIK_PASSWORD = config.secretspec.secrets.MIKROTIK_PASSWORD or "";
  };

  packages = [
    pkgs.secretspec
  ];

  languages.python = {
    enable = true;
    version = lib.strings.trim (builtins.readFile ./.python-version);
    venv.enable = true;
    uv = {
      enable = true;
      sync = {
        enable = true;
        allExtras = true;
      };
    };
  };
}
