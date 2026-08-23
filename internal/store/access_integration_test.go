package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/olivermarcusson/claustra/internal/store"
)

func openTestStore(t *testing.T) (*store.Store, context.Context) {
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
	return st, ctx
}

// makeUser creates an account, optionally carrying an email that is either
// verified or deliberately left unverified.
func makeUser(t *testing.T, st *store.Store, ctx context.Context, email string, verified bool) uuid.UUID {
	t.Helper()
	user := store.User{ID: uuid.New(), WebAuthnHandle: []byte(uuid.NewString()), Status: "active", CreatedAt: time.Now().UTC()}
	credential := webauthn.Credential{ID: []byte(uuid.NewString()), PublicKey: []byte("public")}
	if _, _, err := st.CreateUserWithCredential(ctx, user, credential, "Test", nil); err != nil {
		t.Fatal(err)
	}
	if email == "" {
		return user.ID
	}
	if verified {
		if err := st.VerifyEmail(ctx, user.ID, email, email); err != nil {
			t.Fatal(err)
		}
		return user.ID
	}
	// Claustra only writes user_emails on verification, so an unverified
	// address has to be planted directly to be testable at all.
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_emails(user_id,email,normalized_email,verified_at) VALUES($1,$2,$3,NULL)`, user.ID, email, email); err != nil {
		t.Fatal(err)
	}
	return user.ID
}

func makeClient(t *testing.T, st *store.Store, ctx context.Context, owner uuid.UUID, policy string) string {
	t.Helper()
	id := "acl-" + uuid.NewString()[:8]
	client := store.NewClient{
		Client:     store.Client{ID: id, Name: "Access Test", AccessPolicy: policy, RedirectURIs: []string{"https://client.example/callback"}, AllowedScopes: []string{"openid"}},
		SecretHash: store.HashSecret("secret-" + id),
		CreatedBy:  owner,
	}
	if _, err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	return id
}

func randomEmail(prefix string) string {
	return prefix + "-" + uuid.NewString()[:8] + "@example.com"
}

func mustAllow(t *testing.T, st *store.Store, ctx context.Context, clientID string, userID uuid.UUID, want bool, what string) {
	t.Helper()
	got, err := st.ClientAccessAllowed(ctx, clientID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s: allowed=%v, want %v", what, got, want)
	}
}

func TestClientAccessPolicy(t *testing.T) {
	st, ctx := openTestStore(t)
	owner := makeUser(t, st, ctx, "", false)

	t.Run("open admits any account", func(t *testing.T) {
		id := makeClient(t, st, ctx, owner, store.AccessOpen)
		stranger := makeUser(t, st, ctx, "", false)
		mustAllow(t, st, ctx, id, stranger, true, "open policy, no email")
	})

	t.Run("allowlist denies an unlisted account", func(t *testing.T) {
		id := makeClient(t, st, ctx, owner, store.AccessAllowlist)
		stranger := makeUser(t, st, ctx, randomEmail("stranger"), true)
		mustAllow(t, st, ctx, id, stranger, false, "allowlist, not listed")
	})

	t.Run("allowlist admits a listed verified address", func(t *testing.T) {
		id := makeClient(t, st, ctx, owner, store.AccessAllowlist)
		email := randomEmail("owner")
		user := makeUser(t, st, ctx, email, true)
		if err := st.AllowClientEmail(ctx, id, email, owner); err != nil {
			t.Fatal(err)
		}
		mustAllow(t, st, ctx, id, user, true, "allowlist, listed and verified")
	})

	// The whole reason the match is on verified addresses: registration is
	// public, so a self-asserted address must never open a gated service.
	t.Run("an unverified address never counts", func(t *testing.T) {
		id := makeClient(t, st, ctx, owner, store.AccessAllowlist)
		email := randomEmail("unverified")
		imposter := makeUser(t, st, ctx, email, false)
		if err := st.AllowClientEmail(ctx, id, email, owner); err != nil {
			t.Fatal(err)
		}
		mustAllow(t, st, ctx, id, imposter, false, "allowlist, listed but unverified")
	})

	t.Run("a new client defaults to admitting nobody", func(t *testing.T) {
		// An empty policy is what a caller that forgot the field passes.
		id := makeClient(t, st, ctx, owner, "")
		user := makeUser(t, st, ctx, randomEmail("anyone"), true)
		mustAllow(t, st, ctx, id, user, false, "policy left unset")
	})

	t.Run("a disabled client admits nobody", func(t *testing.T) {
		id := makeClient(t, st, ctx, owner, store.AccessOpen)
		user := makeUser(t, st, ctx, "", false)
		mustAllow(t, st, ctx, id, user, true, "before disabling")
		if err := st.SetClientEnabled(ctx, id, false); err != nil {
			t.Fatal(err)
		}
		mustAllow(t, st, ctx, id, user, false, "after disabling")
	})

	t.Run("an unknown client admits nobody", func(t *testing.T) {
		mustAllow(t, st, ctx, "does-not-exist", owner, false, "unknown client")
	})
}

// Removing an address must not leave the tokens it already holds working.
func TestDenyClientEmailRevokesTokens(t *testing.T) {
	st, ctx := openTestStore(t)
	owner := makeUser(t, st, ctx, "", false)
	email := randomEmail("revoke")
	user := makeUser(t, st, ctx, email, true)
	id := makeClient(t, st, ctx, owner, store.AccessAllowlist)
	if err := st.AllowClientEmail(ctx, id, email, owner); err != nil {
		t.Fatal(err)
	}

	raw := "token-" + uuid.NewString()
	token := store.AccessToken{Hash: store.HashSecret(raw), UserID: user, ClientID: id, Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour)}
	if err := st.PutAccessToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AccessTokenByRaw(ctx, raw); err != nil {
		t.Fatalf("token should be live before revocation: %v", err)
	}

	if err := st.DenyClientEmail(ctx, id, email); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AccessTokenByRaw(ctx, raw); err == nil {
		t.Fatal("access token still valid after the address was removed")
	}
	mustAllow(t, st, ctx, id, user, false, "after removal")
}

// Switching a client from open to allowlist locks out everyone not listed, and
// has to take their live tokens with it.
func TestSetClientAccessPolicyRevokesTokens(t *testing.T) {
	st, ctx := openTestStore(t)
	owner := makeUser(t, st, ctx, "", false)
	user := makeUser(t, st, ctx, randomEmail("closing"), true)
	id := makeClient(t, st, ctx, owner, store.AccessOpen)

	raw := "token-" + uuid.NewString()
	if err := st.PutAccessToken(ctx, store.AccessToken{Hash: store.HashSecret(raw), UserID: user, ClientID: id, Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetClientAccessPolicy(ctx, id, store.AccessAllowlist); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AccessTokenByRaw(ctx, raw); err == nil {
		t.Fatal("access token survived the switch to allowlist")
	}
	mustAllow(t, st, ctx, id, user, false, "after closing the client")

	if err := st.SetClientAccessPolicy(ctx, id, "nonsense"); err == nil {
		t.Fatal("an unknown policy was accepted")
	}
}

func TestForwardHostAccessPolicy(t *testing.T) {
	st, ctx := openTestStore(t)
	owner := makeUser(t, st, ctx, "", false)
	host := "acl-" + uuid.NewString()[:8] + ".example.com"
	email := randomEmail("fwd")
	user := makeUser(t, st, ctx, email, true)

	if err := st.CreateForwardHost(ctx, host, "Access Test", store.AccessAllowlist, owner); err != nil {
		t.Fatal(err)
	}
	allowed, err := st.ForwardAccessAllowed(ctx, host, user)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("an empty allowlist admitted a user")
	}
	if err = st.AllowForwardEmail(ctx, host, email, owner); err != nil {
		t.Fatal(err)
	}
	if allowed, err = st.ForwardAccessAllowed(ctx, host, user); err != nil || !allowed {
		t.Fatalf("listed address denied: allowed=%v err=%v", allowed, err)
	}

	hosts, err := st.ListForwardHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, h := range hosts {
		if h.Host != host {
			continue
		}
		found = true
		if !h.Gated() || len(h.AllowedEmails) != 1 || h.AllowedEmails[0] != email {
			t.Fatalf("host view lost its allowlist: %+v", h)
		}
	}
	if !found {
		t.Fatal("host missing from the listing")
	}

	if err = st.DenyForwardEmail(ctx, host, email); err != nil {
		t.Fatal(err)
	}
	if allowed, err = st.ForwardAccessAllowed(ctx, host, user); err != nil || allowed {
		t.Fatalf("removed address still admitted: allowed=%v err=%v", allowed, err)
	}
}
