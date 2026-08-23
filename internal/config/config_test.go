package config

import "testing"

func validEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("CLAUSTRA_ISSUER", "https://claustra.example")
	t.Setenv("CLAUSTRA_DATABASE_URL", "postgres://example")
	t.Setenv("CLAUSTRA_SIGNING_KEY_FILE", "/secret/key.pem")
	t.Setenv("CLAUSTRA_SECURE_COOKIES", "true")
	t.Setenv("CLAUSTRA_RP_ID", "")
}
func TestLoad(t *testing.T) {
	validEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RPID != "claustra.example" {
		t.Fatalf("RP ID %s", cfg.RPID)
	}
}
func TestRejectsBroadRPID(t *testing.T) {
	validEnvironment(t)
	t.Setenv("CLAUSTRA_RP_ID", "example")
	if _, err := Load(); err == nil {
		t.Fatal("accepted an RP ID different from the issuer host")
	}
}
func TestRejectsInsecureProductionCookies(t *testing.T) {
	validEnvironment(t)
	t.Setenv("CLAUSTRA_SECURE_COOKIES", "false")
	if _, err := Load(); err == nil {
		t.Fatal("accepted insecure cookies for HTTPS")
	}
}
func TestAllowsLocalHTTP(t *testing.T) {
	validEnvironment(t)
	t.Setenv("CLAUSTRA_ISSUER", "http://127.0.0.1:13002")
	t.Setenv("CLAUSTRA_SECURE_COOKIES", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RPID != "127.0.0.1" {
		t.Fatal(cfg.RPID)
	}
}
