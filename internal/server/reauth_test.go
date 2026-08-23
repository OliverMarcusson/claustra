package server

import (
	"bytes"
	"html"
	"html/template"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// TestReauthPageOffersAWayThrough covers the dead end: the old response was
// plain text telling the reader to sign out and in, on a page with no links
// and no sign-out control anywhere in reach.
func TestReauthPageOffersAWayThrough(t *testing.T) {
	tmpl, err := template.New("root").Funcs(templateFuncs).Parse(pageTemplates)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "reauth", map[string]any{
		"Title": "Confirm it is you", "SignedIn": true, "Admin": true,
		"LogoutCSRF": "logout-token", "Continue": "/admin/clients",
	})
	if err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	for _, want := range []string{
		`action="/logout"`, // a sign-out that exists
		"logout-token",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("re-auth page is missing %q", want)
		}
	}
	// html/template percent-escapes the query value, so assert on what the
	// link actually resolves to rather than on its spelling.
	match := regexp.MustCompile(`href="(/login\?continue=[^"]*)"`).FindStringSubmatch(page)
	if match == nil {
		t.Fatal("re-auth page offers no link back to the passkey ceremony")
	}
	link, err := url.Parse(html.UnescapeString(match[1]))
	if err != nil {
		t.Fatal(err)
	}
	if got := link.Query().Get("continue"); got != "/admin/clients" {
		t.Errorf("ceremony returns to %q, not the page that was asked for", got)
	}
	if got := safeContinuation(link.Query().Get("continue")); got != "/admin/clients" {
		t.Errorf("the server would redirect to %q", got)
	}
	if strings.Contains(page, "Sign out and sign in again") {
		t.Error("page still tells the reader to sign out first")
	}
}

// TestSignedInPagesCarryASignOut is the discoverability guard: every page a
// signed-in person lands on must offer sign-out from the header.
func TestSignedInPagesCarryASignOut(t *testing.T) {
	tmpl, err := template.New("root").Funcs(templateFuncs).Parse(pageTemplates)
	if err != nil {
		t.Fatal(err)
	}
	for page, data := range samplePages() {
		values, ok := data.(map[string]any)
		if !ok || values["SignedIn"] != true {
			continue
		}
		values["LogoutCSRF"] = "logout-token"
		name := strings.Split(page, "_out")[0]
		if page == "home_in" {
			name = "home"
		}
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, values); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		if !bytes.Contains(buf.Bytes(), []byte(`action="/logout"`)) {
			t.Errorf("%s: a signed-in page with no way to sign out", page)
		}
	}
}

// TestReauthTargetComesBack checks a GET returns to the page asked for and a
// POST, which cannot be replayed, falls back to the form's own page.
func TestReauthTargetComesBack(t *testing.T) {
	get := httptest.NewRequest("GET", "/admin/clients", nil)
	if got := reauthTarget(get); got != "/admin/clients" {
		t.Errorf("GET target %q", got)
	}
	post := httptest.NewRequest("POST", "/profile", nil)
	post.Header.Set("Referer", "http://"+post.Host+"/account")
	if got := reauthTarget(post); got != "/account" {
		t.Errorf("POST target %q", got)
	}
	bare := httptest.NewRequest("POST", "/profile", nil)
	if got := reauthTarget(bare); got != "/account" {
		t.Errorf("refererless POST target %q", got)
	}
	evil := httptest.NewRequest("POST", "/profile", nil)
	evil.Header.Set("Referer", "https://evil.example/admin")
	if got := reauthTarget(evil); got != "/account" {
		t.Errorf("cross-origin referer leaked through as %q", got)
	}
}
