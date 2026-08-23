package store

import "testing"

func TestNormalizeScopes(t *testing.T) {
	got, err := NormalizeScopes("email openid profile openid")
	if err != nil {
		t.Fatal(err)
	}
	want := "email,openid,profile"
	joined := got[0] + "," + got[1] + "," + got[2]
	if joined != want {
		t.Fatalf("got %s", joined)
	}
	if _, err = NormalizeScopes("profile"); err == nil {
		t.Fatal("accepted request without openid")
	}
	if _, err = NormalizeScopes("openid admin"); err == nil {
		t.Fatal("accepted unknown scope")
	}
}
func TestValidHTTPSURL(t *testing.T) {
	for _, v := range []string{"https://service.example/callback", "https://service.example/path?x=1"} {
		if !ValidHTTPSURL(v) {
			t.Errorf("rejected %s", v)
		}
	}
	for _, v := range []string{"http://service.example/callback", "https://", "javascript:alert(1)", "https://user@service.example/"} {
		if ValidHTTPSURL(v) {
			t.Errorf("accepted %s", v)
		}
	}
}
