{ self }:
{ config, lib, pkgs, ... }:
let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.claustra;
  issuerHost = builtins.head (builtins.match "https://([^/]+)/?" cfg.issuer);
  localDatabaseURL = "postgres:///claustra?host=/run/postgresql";
in {
  options.services.claustra = {
    enable = mkEnableOption "Claustra identity provider";
    package = mkOption { type = types.package; default = self.packages.${pkgs.system}.default; };
    issuer = mkOption { type = types.str; default = "https://claustra.marcusson.dev"; };
    rpId = mkOption { type = types.str; default = issuerHost; };
    listenAddress = mkOption { type = types.str; default = "127.0.0.1:13002"; };
    environmentFile = mkOption { type = types.nullOr types.str; default = null; description = "Root-managed environment file for SMTP and external database secrets; do not use a Nix store path."; };
    signingKeyFile = mkOption { type = types.str; default = "/var/lib/claustra/signing-key.pem"; };
    previousSigningKeyFiles = mkOption { type = types.listOf types.str; default = [ ]; };
    localPostgres = mkOption { type = types.bool; default = true; };
    caddy = mkOption { type = types.bool; default = true; };
    backup = {
      enable = mkEnableOption "daily encrypted Claustra backups";
      directory = mkOption { type = types.str; default = "/var/backup/claustra"; };
      ageRecipient = mkOption { type = types.str; default = ""; description = "Public age recipient used to encrypt backups."; };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      { assertion = builtins.match "https://[^/]+/?" cfg.issuer != null; message = "services.claustra.issuer must be an HTTPS origin without a path"; }
      { assertion = !cfg.backup.enable || cfg.backup.ageRecipient != ""; message = "services.claustra.backup.ageRecipient is required when backups are enabled"; }
      { assertion = cfg.localPostgres || cfg.environmentFile != null; message = "An environmentFile containing CLAUSTRA_DATABASE_URL is required when localPostgres is disabled"; }
    ];

    users.groups.claustra = { };
    users.users.claustra = { isSystemUser = true; group = "claustra"; extraGroups = lib.optional cfg.localPostgres "postgres"; };

    services.postgresql = mkIf cfg.localPostgres {
      enable = true;
      ensureDatabases = [ "claustra" ];
      ensureUsers = [{ name = "claustra"; ensureDBOwnership = true; }];
    };

    services.caddy = mkIf cfg.caddy {
      enable = true;
      virtualHosts.${issuerHost}.extraConfig = "reverse_proxy ${cfg.listenAddress}";
    };

    systemd.services.claustra = {
      description = "Claustra identity provider";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ] ++ lib.optional cfg.localPostgres "postgresql.service";
      wants = [ "network-online.target" ];
      environment = {
        CLAUSTRA_ISSUER = cfg.issuer;
        CLAUSTRA_RP_ID = cfg.rpId;
        CLAUSTRA_LISTEN_ADDR = cfg.listenAddress;
        CLAUSTRA_SIGNING_KEY_FILE = cfg.signingKeyFile;
        CLAUSTRA_PREVIOUS_SIGNING_KEY_FILES = lib.concatStringsSep "," cfg.previousSigningKeyFiles;
      } // lib.optionalAttrs cfg.localPostgres { CLAUSTRA_DATABASE_URL = localDatabaseURL; };
      preStart = "test -s ${lib.escapeShellArg cfg.signingKeyFile} || ${cfg.package}/bin/claustra keygen ${lib.escapeShellArg cfg.signingKeyFile}";
      serviceConfig = {
        Type = "simple";
        User = "claustra";
        Group = "claustra";
        ExecStart = "${cfg.package}/bin/claustra serve";
        EnvironmentFile = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
        StateDirectory = "claustra";
        StateDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = "2s";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectClock = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        SystemCallArchitectures = "native";
      };
    };

    # ProtectSystem=strict makes the whole filesystem read-only for the backup
    # unit except ReadWritePaths, and systemd fails namespace setup outright if
    # such a path does not exist. The script's own mkdir never gets to run, so
    # the directory has to exist before the unit starts: hence tmpfiles rather
    # than ExecStartPre, which would be inside the same namespace.
    systemd.tmpfiles.rules = lib.optional cfg.backup.enable
      "d ${cfg.backup.directory} 0700 claustra claustra -";

    systemd.services.claustra-backup = mkIf cfg.backup.enable {
      description = "Encrypted Claustra backup";
      after = [ "claustra.service" ] ++ lib.optional cfg.localPostgres "postgresql.service";
      path = [ pkgs.bash pkgs.postgresql pkgs.age pkgs.gnutar pkgs.coreutils pkgs.findutils ];
      environment = {
        CLAUSTRA_BACKUP_DIR = cfg.backup.directory;
        CLAUSTRA_BACKUP_AGE_RECIPIENT = cfg.backup.ageRecipient;
        CLAUSTRA_SIGNING_KEY_FILE = cfg.signingKeyFile;
        CLAUSTRA_PREVIOUS_SIGNING_KEY_FILES = lib.concatStringsSep "," cfg.previousSigningKeyFiles;
        CLAUSTRA_CONFIG_FILE = if cfg.environmentFile == null then "" else cfg.environmentFile;
      } // lib.optionalAttrs cfg.localPostgres { CLAUSTRA_BACKUP_DATABASE_URL = localDatabaseURL; };
      serviceConfig = {
        Type = "oneshot";
        User = "claustra";
        Group = "claustra";
        ExecStart = "${cfg.package}/bin/claustra-backup";
        ReadWritePaths = [ cfg.backup.directory ];
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
      };
    };
    systemd.timers.claustra-backup = mkIf cfg.backup.enable {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnCalendar = "daily"; Persistent = true; RandomizedDelaySec = "30m"; };
    };
  };
}
