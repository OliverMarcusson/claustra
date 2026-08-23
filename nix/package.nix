{ lib, buildGoModule }:
buildGoModule {
  pname = "claustra";
  version = "0.1.0";
  src = lib.cleanSource ../.;
  vendorHash = "sha256-pFE8Log07V6sGcvsU5i4XBWyMs0GhP7pMsDLlEuDUoc=";

  subPackages = [ "cmd/claustra" ];
  ldflags = [ "-s" "-w" ];
  env.CGO_ENABLED = 0;

  # patchShebangs explicitly: the script arrives from the store as its own
  # path, and its #!/usr/bin/env bash survived into $out otherwise. systemd
  # units get a PATH built from their own `path` list, which does not carry a
  # shell, so an unpatched shebang fails with env: bash: No such file.
  postInstall = ''
    install -Dm755 ${../scripts/backup.sh} $out/bin/claustra-backup
    patchShebangs $out/bin/claustra-backup
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
