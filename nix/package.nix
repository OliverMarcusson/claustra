{ lib, buildGoModule, bash }:
buildGoModule {
  pname = "claustra";
  version = "0.1.0";
  src = lib.cleanSource ../.;
  vendorHash = "sha256-pFE8Log07V6sGcvsU5i4XBWyMs0GhP7pMsDLlEuDUoc=";

  subPackages = [ "cmd/claustra" ];
  ldflags = [ "-s" "-w" ];
  env.CGO_ENABLED = 0;

  # The shebang is rewritten by hand rather than left to patchShebangs, which
  # does not reach this file: it is installed from its own store path and the
  # #!/usr/bin/env bash reached $out untouched. A systemd unit's PATH is built
  # from its own `path` list and carries no shell, so the unit then dies with
  # env: bash: No such file or directory.
  postInstall = ''
    install -Dm755 ${../scripts/backup.sh} $out/bin/claustra-backup
    substituteInPlace $out/bin/claustra-backup --replace-fail '#!/usr/bin/env bash' '#!${bash}/bin/bash'
  '';

  doCheck = true;
  meta = {
    description = "Passkey-first OpenID Connect provider";
    homepage = "https://github.com/olivermarcusson/claustra";
    license = lib.licenses.mit;
    mainProgram = "claustra";
    platforms = lib.platforms.linux;
  };
}
