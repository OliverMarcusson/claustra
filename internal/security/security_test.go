package security

import "testing"

func TestPKCEChallenge(t *testing.T) {
	got := PKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("RFC 7636 vector mismatch: %s", got)
	}
}

func TestCSRF(t *testing.T) {
	v := CSRF("secret", "consent")
	if !ValidateCSRF("secret", "consent", v) {
		t.Fatal("valid token rejected")
	}
	if ValidateCSRF("different", "consent", v) {
		t.Fatal("invalid token accepted")
	}
}
