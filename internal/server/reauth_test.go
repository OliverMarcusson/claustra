package server

import (
	"bytes"
	"html/template"
	"net/http/httptest"
	"reflect"
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
	// The ceremony runs on this page rather than sending the reader to yet
	// another one to press a second button.
	for _, want := range []string{
		`id="passkey"`,
		`data-begin="/webauthn/login/begin"`,
		`data-continue="/admin/clients"`,
		`src="/static/passkey.js"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("re-auth page cannot run the ceremony itself: missing %q", want)
		}
	}
	if strings.Contains(page, `href="/login`) {
		t.Error("re-auth still bounces through the sign-in page")
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

// TestPendingSubmissionSurvivesReauth is the regression guard for a silently
// destructive bounce: a profile save was turned away for re-authentication,
// the ceremony succeeded, and the typed address was gone with nothing said.
func TestPendingSubmissionSurvivesReauth(t *testing.T) {
	body := "csrf=stale-token&display_name=Oliver+M&email=oliver%40marcusson.dev"
	r := httptest.NewRequest("POST", "/profile", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pending := pendingSubmission(httptest.NewRecorder(), r)
	if pending == nil {
		t.Fatal("the blocked form was dropped instead of carried through re-auth")
	}
	if pending.Action != "/profile" || pending.CSRFScope != "account" {
		t.Errorf("resume targets %q scope %q", pending.Action, pending.CSRFScope)
	}
	want := []resumeField{{"display_name", "Oliver M"}, {"email", "oliver@marcusson.dev"}}
	if !reflect.DeepEqual(pending.Fields, want) {
		t.Errorf("carried %v, want %v", pending.Fields, want)
	}
	// The posted token belongs to the session the ceremony replaces.
	for _, field := range pending.Fields {
		if field.Name == "csrf" {
			t.Error("a CSRF token bound to the outgoing session was carried over")
		}
	}
}

func TestPendingSubmissionOnlyCarriesReplayableForms(t *testing.T) {
	admin := httptest.NewRequest("POST", "/admin/clients", strings.NewReader("id=euripus"))
	admin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if pending := pendingSubmission(httptest.NewRecorder(), admin); pending == nil || pending.CSRFScope != "admin-clients" {
		t.Error("an admin form does not get an admin-scoped token")
	}
	// A fetch body cannot be rebuilt from hidden inputs, and reading it here
	// would consume it before the real handler runs.
	fetch := httptest.NewRequest("POST", "/webauthn/passkey/begin", strings.NewReader(`{"continue":"/account"}`))
	fetch.Header.Set("Content-Type", "application/json")
	if pendingSubmission(httptest.NewRecorder(), fetch) != nil {
		t.Error("a JSON body was consumed and turned into hidden inputs")
	}
	upload := httptest.NewRequest("POST", "/profile/avatar", strings.NewReader("binary"))
	upload.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	if pendingSubmission(httptest.NewRecorder(), upload) != nil {
		t.Error("a multipart upload was treated as replayable")
	}
	if pendingSubmission(httptest.NewRecorder(), httptest.NewRequest("GET", "/admin/clients", nil)) != nil {
		t.Error("a GET needs no resume: data-continue already repeats it")
	}
}

func TestResumableCSRFScopeIsAnAllowlist(t *testing.T) {
	for _, ok := range []string{"account", "admin-clients"} {
		if resumableCSRFScope(ok) != ok {
			t.Errorf("%q should be mintable", ok)
		}
	}
	for _, bad := range []string{"consent", "", "../account", "admin"} {
		if got := resumableCSRFScope(bad); got != "" {
			t.Errorf("%q minted a token for %q", bad, got)
		}
	}
}

// TestReauthPageReplaysTheBlockedForm checks the page carries the submission
// and leaves the token blank: it is stamped in from the ceremony's response,
// because finishing re-auth issues a new session and kills the old token.
func TestReauthPageReplaysTheBlockedForm(t *testing.T) {
	tmpl, err := template.New("root").Funcs(templateFuncs).Parse(pageTemplates)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "reauth", map[string]any{
		"Title": "Confirm it is you", "SignedIn": true, "LogoutCSRF": "logout-token",
		"Continue": "/account",
		"Resume": &resumable{Action: "/profile", CSRFScope: "account", Fields: []resumeField{
			{"display_name", "Oliver M"}, {"email", "oliver@marcusson.dev"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	for _, want := range []string{
		`id="resume"`,
		`action="/profile"`,
		`data-csrf-scope="account"`,
		`name="display_name" value="Oliver M"`,
		`name="email" value="oliver@marcusson.dev"`,
		`name="csrf" value=""`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("re-auth page cannot replay the save: missing %q", want)
		}
	}
}

// TestRevokedPasskeyIsNamedAsRevoked pins the three ways a discoverable login
// finds nothing apart. Revoking a passkey leaves it in the authenticator, so
// it keeps being offered - and calling that "not registered here" points the
// reader at creating an account instead of picking their other passkey.
func TestRevokedPasskeyIsNamedAsRevoked(t *testing.T) {
	for _, c := range []struct{ state, want string }{
		{"revoked", "that passkey was revoked - use a different one"},
		{"", "that passkey is not registered here - pick another, or create an account"},
		{"active", "passkey assertion was not valid"},
	} {
		if got := assertionFailureMessage(true, c.state, c.state != ""); got != c.want {
			t.Errorf("state %q gave %q, want %q", c.state, got, c.want)
		}
	}
	if got := assertionFailureMessage(false, "", false); got != "passkey assertion was not valid" {
		t.Errorf("a genuine validation failure said %q", got)
	}
}
