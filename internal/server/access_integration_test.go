package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/olivermarcusson/claustra/internal/config"
	"github.com/olivermarcusson/claustra/internal/store"
)

// accessFixture is a running App backed by the test database, plus one signed-in
// account holding a verified address.
type accessFixture struct {
	app     *App
	st      *store.Store
	ctx     context.Context
	userID  uuid.UUID
	email   string
	session string
}

func newAccessFixture(t *testing.T) accessFixture {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err = st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("root").Funcs(templateFuncs).Parse(pageTemplates)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{
		Config: config.Config{
			Issuer: "https://claustra.example", AccessTokenTTL: 15 * time.Minute, IDTokenTTL: 5 * time.Minute,
			CodeTTL: time.Minute, SessionIdleTTL: time.Hour, SessionAbsoluteTTL: 24 * time.Hour,
		},
		Store: st, SigningKey: key, SigningKeyID: "test-key", Templates: tmpl, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	user := store.User{ID: uuid.New(), WebAuthnHandle: []byte(uuid.NewString()), Status: "active", CreatedAt: time.Now().UTC()}
	credential := webauthn.Credential{ID: []byte(uuid.NewString()), PublicKey: []byte("public")}
	if _, _, err = st.CreateUserWithCredential(ctx, user, credential, "Test", nil); err != nil {
		t.Fatal(err)
	}
	email := "gate-" + uuid.NewString()[:8] + "@example.com"
	if err = st.VerifyEmail(ctx, user.ID, email, email); err != nil {
		t.Fatal(err)
	}

	raw := "session-" + uuid.NewString()
	now := time.Now().UTC()
	session := store.Session{
		Hash: store.HashSecret(raw), UserID: user.ID, AuthTime: now, CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour),
	}
	if err = st.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	return accessFixture{app: app, st: st, ctx: ctx, userID: user.ID, email: email, session: raw}
}

// authorizeRequest issues a well-formed authorization request as the fixture's
// signed-in user.
func (f accessFixture) authorizeRequest(clientID string) *httptest.ResponseRecorder {
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {"https://client.example/callback"},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"state-value"}, "nonce": {"nonce-value"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	r := httptest.NewRequest(http.MethodGet, "https://claustra.example/authorize?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: f.app.sessionCookieName(), Value: f.session})
	w := httptest.NewRecorder()
	f.app.authorize(w, r)
	return w
}

func (f accessFixture) newClient(t *testing.T, policy string) string {
	t.Helper()
	id := "gate-" + uuid.NewString()[:8]
	client := store.NewClient{
		Client: store.Client{
			ID: id, Name: "Gated Service", AccessPolicy: policy,
			RedirectURIs: []string{"https://client.example/callback"},
			// Trusted with openid preapproved, so a permitted request goes
			// straight to a code and an unpermitted one cannot be mistaken
			// for the consent page.
			Trusted: true, AllowedScopes: []string{"openid"}, PreapprovedScopes: []string{"openid"},
		},
		SecretHash: store.HashSecret("secret-" + id),
		CreatedBy:  f.userID,
	}
	if _, err := f.st.CreateClient(f.ctx, client); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestAuthorizeEnforcesTheAllowlist is the test the existing OIDC integration
// test cannot be: that one plants an authorization code directly and starts at
// /token, so it never exercises the authorization endpoint at all.
func TestAuthorizeEnforcesTheAllowlist(t *testing.T) {
	f := newAccessFixture(t)

	t.Run("a gated client turns away an unlisted account", func(t *testing.T) {
		id := f.newClient(t, store.AccessAllowlist)
		w := f.authorizeRequest(id)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "No access to Gated Service") {
			t.Errorf("the denial page does not name the service:\n%s", body)
		}
		// A bounce back to the client would loop: the client would send the
		// browser straight back to /authorize.
		if location := w.Header().Get("Location"); location != "" {
			t.Errorf("denied request redirected to %q instead of explaining itself", location)
		}
	})

	t.Run("listing the address lets the same request through", func(t *testing.T) {
		id := f.newClient(t, store.AccessAllowlist)
		if err := f.st.AllowClientEmail(f.ctx, id, f.email, f.userID); err != nil {
			t.Fatal(err)
		}
		w := f.authorizeRequest(id)
		if w.Code != http.StatusFound {
			t.Fatalf("status %d, want 302: %s", w.Code, w.Body.String())
		}
		location := w.Header().Get("Location")
		if !strings.HasPrefix(location, "https://client.example/callback?") || !strings.Contains(location, "code=") {
			t.Fatalf("no authorization code was issued: %q", location)
		}
	})

	t.Run("an open client admits the account without listing it", func(t *testing.T) {
		id := f.newClient(t, store.AccessOpen)
		if w := f.authorizeRequest(id); w.Code != http.StatusFound {
			t.Fatalf("status %d, want 302: %s", w.Code, w.Body.String())
		}
	})

	// Removing the address mid-flight must not leave a usable code behind.
	t.Run("a code stops redeeming once access is withdrawn", func(t *testing.T) {
		id := f.newClient(t, store.AccessAllowlist)
		if err := f.st.AllowClientEmail(f.ctx, id, f.email, f.userID); err != nil {
			t.Fatal(err)
		}
		w := f.authorizeRequest(id)
		if w.Code != http.StatusFound {
			t.Fatalf("setup: status %d", w.Code)
		}
		issued, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		code := issued.Query().Get("code")
		if code == "" {
			t.Fatal("setup: no code issued")
		}
		if err = f.st.DenyClientEmail(f.ctx, id, f.email); err != nil {
			t.Fatal(err)
		}

		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri":  {"https://client.example/callback"},
			"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		}
		tr := httptest.NewRequest(http.MethodPost, "https://claustra.example/token", strings.NewReader(form.Encode()))
		tr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tr.SetBasicAuth(id, "secret-"+id)
		tw := httptest.NewRecorder()
		f.app.token(tw, tr)
		if tw.Code == http.StatusOK {
			t.Fatalf("the code still redeemed after access was withdrawn: %s", tw.Body.String())
		}
	})
}

func TestForwardAuthorizeEnforcesTheAllowlist(t *testing.T) {
	f := newAccessFixture(t)
	host := "gate-" + uuid.NewString()[:8] + ".example.com"
	if err := f.st.CreateForwardHost(f.ctx, host, "Gated Host", store.AccessAllowlist, f.userID); err != nil {
		t.Fatal(err)
	}

	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://claustra.example/forward-auth/authorize?host="+host+"&rd=%2F", nil)
		r.AddCookie(&http.Cookie{Name: f.app.sessionCookieName(), Value: f.session})
		w := httptest.NewRecorder()
		f.app.forwardAuthorize(w, r)
		return w
	}

	w := request()
	if w.Code != http.StatusForbidden {
		t.Fatalf("unlisted account got status %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No access to Gated Host") {
		t.Error("the denial page does not name the host")
	}

	if err := f.st.AllowForwardEmail(f.ctx, host, f.email, f.userID); err != nil {
		t.Fatal(err)
	}
	w = request()
	if w.Code != http.StatusFound {
		t.Fatalf("listed account got status %d, want 302: %s", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(w.Header().Get("Location"), "https://"+host+"/_claustra/callback?ticket=") {
		t.Fatalf("no ticket issued: %q", w.Header().Get("Location"))
	}
}

// authorizeWith issues an authorization request carrying extra parameters.
func (f accessFixture) authorizeWith(clientID string, extra url.Values) *httptest.ResponseRecorder {
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {"https://client.example/callback"},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"state-value"}, "nonce": {"nonce-value"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	r := httptest.NewRequest(http.MethodGet, "https://claustra.example/authorize?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: f.app.sessionCookieName(), Value: f.session})
	w := httptest.NewRecorder()
	f.app.authorize(w, r)
	return w
}

// A service that uses passkeys to confirm a destructive action, rather than
// merely to log someone in, needs the provider to re-run the ceremony on
// demand. Without prompt/max_age, Claustra could replace a login but not a
// confirmation.
func TestAuthorizeStepUp(t *testing.T) {
	f := newAccessFixture(t)
	id := f.newClient(t, store.AccessOpen)

	t.Run("a live session alone satisfies an ordinary request", func(t *testing.T) {
		if w := f.authorizeWith(id, nil); w.Code != http.StatusFound {
			t.Fatalf("status %d, want 302", w.Code)
		}
	})

	t.Run("prompt=login re-runs the ceremony", func(t *testing.T) {
		w := f.authorizeWith(id, url.Values{"prompt": {"login"}})
		if w.Code != http.StatusOK {
			t.Fatalf("status %d, want the ceremony page", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, `data-begin="/webauthn/login/begin"`) {
			t.Error("the step-up page does not run the passkey ceremony")
		}
		// Carrying prompt=login into the continuation would demand the
		// ceremony again the instant it succeeded.
		if strings.Contains(body, "prompt=login") {
			t.Error("the continuation still carries prompt=login, which cannot terminate")
		}
		if !strings.Contains(body, `data-continue="/authorize?`) {
			t.Errorf("the ceremony does not return to the authorization request:\n%s", body)
		}
	})

	t.Run("max_age=0 re-runs the ceremony", func(t *testing.T) {
		if w := f.authorizeWith(id, url.Values{"max_age": {"0"}}); w.Code != http.StatusOK {
			t.Fatalf("status %d, want the ceremony page", w.Code)
		}
	})

	// The session in the fixture was authenticated moments ago, so a generous
	// max_age must not trigger a pointless ceremony.
	t.Run("a satisfied max_age passes straight through", func(t *testing.T) {
		if w := f.authorizeWith(id, url.Values{"max_age": {"3600"}}); w.Code != http.StatusFound {
			t.Fatalf("status %d, want 302", w.Code)
		}
	})

	t.Run("prompt=none never shows a page", func(t *testing.T) {
		w := f.authorizeWith(id, url.Values{"prompt": {"none"}, "max_age": {"0"}})
		if w.Code != http.StatusFound {
			t.Fatalf("status %d, want a redirect", w.Code)
		}
		if !strings.Contains(w.Header().Get("Location"), "error=login_required") {
			t.Fatalf("want login_required, got %q", w.Header().Get("Location"))
		}
	})

	t.Run("a nonsense prompt is rejected", func(t *testing.T) {
		w := f.authorizeWith(id, url.Values{"prompt": {"select_account"}})
		if !strings.Contains(w.Header().Get("Location"), "error=invalid_request") {
			t.Fatalf("unsupported prompt accepted: %d %q", w.Code, w.Header().Get("Location"))
		}
	})

	t.Run("a negative max_age is rejected", func(t *testing.T) {
		w := f.authorizeWith(id, url.Values{"max_age": {"-1"}})
		if !strings.Contains(w.Header().Get("Location"), "error=invalid_request") {
			t.Fatalf("negative max_age accepted: %d %q", w.Code, w.Header().Get("Location"))
		}
	})
}
