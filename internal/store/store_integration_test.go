package store

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func TestPostgresLifecycle(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	st, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	handle := make([]byte, 64)
	if _, err = rand.Read(handle); err != nil {
		t.Fatal(err)
	}
	user := User{ID: uuid.New(), WebAuthnHandle: handle, Status: "active", CreatedAt: time.Now().UTC()}
	credential := webauthn.Credential{ID: []byte(uuid.NewString()), PublicKey: []byte("public-key")}
	credentialID, admin, err := st.CreateUserWithCredential(ctx, user, credential, "Test passkey", nil)
	if err != nil {
		t.Fatal(err)
	}
	if admin {
		t.Fatal("ordinary registration became admin")
	}
	loaded, err := st.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Credentials) != 1 {
		t.Fatalf("got %d credentials", len(loaded.Credentials))
	}
	rawSession := "integration-session-" + uuid.NewString()
	now := time.Now().UTC()
	err = st.CreateSession(ctx, Session{Hash: HashSecret(rawSession), UserID: user.ID, CredentialID: &credentialID, AuthTime: now, CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour), IP: "127.0.0.1", UserAgent: "integration-test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.SessionByToken(ctx, rawSession, time.Hour); err != nil {
		t.Fatal(err)
	}
	clientID := "test-" + uuid.NewString()[:8]
	secret := "integration-client-secret"
	_, err = st.CreateClient(ctx, NewClient{Client: Client{ID: clientID, Name: "Integration", RedirectURIs: []string{"https://client.example/callback"}, AllowedScopes: []string{"openid", "profile"}}, SecretHash: HashSecret(secret), CreatedBy: user.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !st.ValidateClientSecret(ctx, clientID, secret) {
		t.Fatal("client secret rejected")
	}
	sub1, err := st.PairwiseSubject(ctx, user.ID, clientID)
	if err != nil {
		t.Fatal(err)
	}
	sub2, err := st.PairwiseSubject(ctx, user.ID, clientID)
	if err != nil || sub1 != sub2 {
		t.Fatal("pairwise subject is not stable")
	}
	codeRaw := "integration-code-" + uuid.NewString()
	err = st.PutAuthorizationCode(ctx, AuthorizationCode{Hash: HashSecret(codeRaw), UserID: user.ID, ClientID: clientID, RedirectURI: "https://client.example/callback", PKCEChallenge: "challenge", Nonce: "nonce", Scopes: []string{"openid"}, AuthTime: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.ConsumeAuthorizationCode(ctx, HashSecret(codeRaw)); err != nil {
		t.Fatal(err)
	}
	if _, err = st.ConsumeAuthorizationCode(ctx, HashSecret(codeRaw)); err == nil {
		t.Fatal("authorization code replay succeeded")
	}
}
