package server

import (
	"image"
	"testing"
)

func TestSafeContinuation(t *testing.T) {
	for _, v := range []string{"/account", "/authorize?x=1"} {
		if got := safeContinuation(v); got != v {
			t.Errorf("%s became %s", v, got)
		}
	}
	for _, v := range []string{"https://evil.example", "//evil.example", "account"} {
		if got := safeContinuation(v); got != "/account" {
			t.Errorf("unsafe %s accepted as %s", v, got)
		}
	}
}
func TestSafeReturnPath(t *testing.T) {
	if got := safeReturnPath("/settings?x=1"); got != "/settings?x=1" {
		t.Fatal(got)
	}
	for _, v := range []string{"https://evil.example", "//evil.example"} {
		if got := safeReturnPath(v); got != "/" {
			t.Errorf("unsafe %s accepted", v)
		}
	}
}
func TestNormalizeEmail(t *testing.T) {
	got, err := normalizeEmail("User@Example.COM")
	if err != nil || got != "user@example.com" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err = normalizeEmail("Name <user@example.com>"); err == nil {
		t.Fatal("accepted display-name address")
	}
}
func TestResizeWithin(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 1200, 600))
	got := resizeWithin(src, 512, 512)
	if got.Bounds().Dx() != 512 || got.Bounds().Dy() != 256 {
		t.Fatalf("got %v", got.Bounds())
	}
}
