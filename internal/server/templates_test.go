package server

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/olivermarcusson/claustra/internal/store"
)

func samplePages() map[string]any {
	now := time.Date(2026, 8, 23, 18, 15, 0, 0, time.UTC)
	used := now.Add(-3 * time.Hour)
	name := "Oliver Marcusson"
	email := "oliver@marcusson.dev"
	user := store.WebAuthnUser{
		User:        store.User{ID: uuid.New(), Status: "active", DisplayName: &name, Email: &email, EmailVerified: true, CreatedAt: now},
		Credentials: []store.Credential{{ID: uuid.New(), Name: "MacBook Touch ID", State: "active", CreatedAt: now, LastUsedAt: &used}, {ID: uuid.New(), Name: "YubiKey 5C", State: "active", CreatedAt: now}},
	}
	client := store.Client{ID: "euripus", Name: "Euripus", HomepageURI: "https://euripus.marcusson.dev", PrivacyPolicyURI: "https://euripus.marcusson.dev/privacy", Trusted: true, Enabled: true, AccessPolicy: store.AccessAllowlist, AllowedEmails: []string{"oliver@marcusson.dev"}}
	return map[string]any{
		"home_out": map[string]any{"SignedIn": false},
		"home_in":  map[string]any{"SignedIn": true, "Admin": true, "User": user},
		"account": map[string]any{"Title": "Account", "SignedIn": true, "NavAccount": true, "HasAvatar": false, "User": user, "Admin": true,
			"CSRF": "csrf-token", "PendingRecovery": true, "RecoveryID": uuid.New(), "RecoveryDue": now.Add(20 * time.Hour),
			"Sessions": []map[string]any{{"Hash": "aGFzaA", "Current": true, "LastSeen": now, "IP": "192.168.0.14", "UserAgent": "Mozilla/5.0 (Windows NT 11.0) Chrome/141"}},
			"Consents": []store.ConsentView{{ClientID: "euripus", ClientName: "Euripus", Scopes: []string{"openid", "profile"}, GrantedAt: now}}},
		"admin_clients": map[string]any{"Title": "Clients", "SignedIn": true, "Admin": true, "NavAdmin": true, "Issuer": "https://claustra.marcusson.dev",
			"CSRF": "csrf-token", "NewSecret": "cs_7f3a91b0c4d2e5a68b1f4c7d0e3a6b9c",
			"Clients":      []store.Client{client, {ID: "mcsn", Name: "mcsn.se", Enabled: false, AccessPolicy: store.AccessOpen}},
			"ForwardHosts": []store.ForwardHost{{Host: "grafana.marcusson.dev", Name: "Grafana", Enabled: true, AccessPolicy: store.AccessAllowlist, AllowedEmails: []string{"oliver@marcusson.dev"}}},
			"Admins":       []store.AdminView{{UserID: uuid.New(), DisplayName: "Oliver Marcusson", Email: "oliver@marcusson.dev", GrantedAt: now}}},
		"consent": map[string]any{"Title": "Authorize", "SignedIn": true, "Client": client, "Scopes": []string{"openid", "profile", "email"},
			"Fields": map[string]string{"client_id": "euripus", "state": "abc"}, "CSRF": "csrf-token"},
		"passkey": map[string]any{"Title": "Sign in", "Heading": "Sign in", "Description": "Use one of the passkeys registered with Claustra.",
			"Button": "Use passkey", "Begin": "/webauthn/login/begin", "Finish": "/webauthn/login/finish", "Method": "get", "Continue": "/account", "Bootstrap": ""},
		"recover": map[string]any{"Title": "Recover", "Sent": true},
		"message": map[string]any{"Title": "Deletion scheduled", "Heading": "Account disabled", "Message": "Your account will be permanently deleted after seven days."},
		"denied":  map[string]any{"Title": "No access", "SignedIn": true, "Admin": false, "Service": "Pagina", "Email": "someone@example.com"},
	}
}

// TestTemplatesRender executes every page so template errors surface in CI
// rather than in a browser.
func TestTemplatesRender(t *testing.T) {
	tmpl, err := template.New("root").Funcs(templateFuncs).Parse(pageTemplates)
	if err != nil {
		t.Fatal(err)
	}
	dump := os.Getenv("CLAUSTRA_TEMPLATE_DUMP")
	for page, data := range samplePages() {
		name := strings.Split(page, "_out")[0]
		if page == "home_in" {
			name = "home"
		}
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		if !bytes.Contains(buf.Bytes(), []byte("</html>")) {
			t.Fatalf("%s: incomplete document", page)
		}
		if dump != "" {
			if err := os.WriteFile(filepath.Join(dump, page+".html"), buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestMailFailurePageRenders covers the page shown when a verification email
// cannot be sent: it is the only mail failure a user sees rather than one the
// log absorbs, so a broken template here would replace it with a blank 503.
func TestMailFailurePageRenders(t *testing.T) {
	tmpl, err := template.New("root").Funcs(templateFuncs).Parse(pageTemplates)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "message", map[string]any{
		"Title": "Email not sent", "SignedIn": true, "Admin": false,
		"Back": "/account", "BackLabel": "Back to your account",
		"Heading": "Verification email could not be sent",
		"Message": "Your display name was saved.",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Verification email could not be sent", "display name was saved", `class="btn" href="/account">Back to your account`} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Fatalf("page is missing %q", want)
		}
	}
}
