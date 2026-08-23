{ lib, buildGoModule }:
buildGoModule {
  pname = "claustra";
  version = "0.1.0";
  src = lib.cleanSource ../.;
  vendorHash = "sha256-pFE8Log07V6sGcvsU5i4XBWyMs0GhP7pMsDLlEuDUoc=";

  subPackages = [ "cmd/claustra" ];
  ldflags = [ "-s" "-w" ];
  env.CGO_ENABLED = 0;

  postInstall = ''
    install -Dm755 ${../scripts/backup.sh} $out/bin/claustra-backup
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
