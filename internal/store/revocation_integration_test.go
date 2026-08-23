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

// revocationFixture creates a user with one passkey, one live session and one
// access token bound to that session, and returns the session token.
func revocationFixture(ctx context.Context, t *testing.T, st *Store) (uuid.UUID, string, string) {
	t.Helper()
	handle := make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		t.Fatal(err)
	}
	user := User{ID: uuid.New(), WebAuthnHandle: handle, Status: "active", CreatedAt: time.Now().UTC()}
	credential := webauthn.Credential{ID: []byte(uuid.NewString()), PublicKey: []byte("public-key")}
	credentialID, _, err := st.CreateUserWithCredential(ctx, user, credential, "Test passkey", nil)
	if err != nil {
		t.Fatal(err)
	}
	rawSession := "revocation-session-" + uuid.NewString()
	now := time.Now().UTC()
	err = st.CreateSession(ctx, Session{Hash: HashSecret(rawSession), UserID: user.ID, CredentialID: &credentialID, AuthTime: now, CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour), IP: "127.0.0.1", UserAgent: "integration-test"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := "revoke-" + uuid.NewString()[:8]
	_, err = st.CreateClient(ctx, NewClient{Client: Client{ID: clientID, Name: "Revocation", RedirectURIs: []string{"https://client.example/callback"}, AllowedScopes: []string{"openid"}}, SecretHash: HashSecret("secret"), CreatedBy: user.ID})
	if err != nil {
		t.Fatal(err)
	}
	rawToken := "revocation-token-" + uuid.NewString()
	err = st.PutAccessToken(ctx, AccessToken{Hash: HashSecret(rawToken), UserID: user.ID, ClientID: clientID, SessionHash: HashSecret(rawSession), Scopes: []string{"openid"}, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return user.ID, rawSession, rawToken
}

func assertRevoked(ctx context.Context, t *testing.T, st *Store, rawSession, rawToken string) {
	t.Helper()
	if _, err := st.SessionByToken(ctx, rawSession, time.Hour); err == nil {
		t.Error("session still resolves after revocation")
	}
	if _, err := st.AccessTokenByRaw(ctx, rawToken); err == nil {
		t.Error("access token still resolves after revocation")
	}
}

// TestRevocation covers every path that ends a session. Each of these used to
// send two UPDATEs in a single parameterised statement, which Postgres rejects
// over the extended query protocol, so nothing was ever revoked.
func TestRevocation(t *testing.T) {
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

	t.Run("owned session", func(t *testing.T) {
		userID, rawSession, rawToken := revocationFixture(ctx, t, st)
		if err := st.RevokeOwnedSession(ctx, userID, HashSecret(rawSession)); err != nil {
			t.Fatal(err)
		}
		assertRevoked(ctx, t, st, rawSession, rawToken)
	})

	t.Run("owned session belonging to someone else", func(t *testing.T) {
		_, rawSession, rawToken := revocationFixture(ctx, t, st)
		if err := st.RevokeOwnedSession(ctx, uuid.New(), HashSecret(rawSession)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.SessionByToken(ctx, rawSession, time.Hour); err != nil {
			t.Error("another user's revoke ended this session")
		}
		if _, err := st.AccessTokenByRaw(ctx, rawToken); err != nil {
			t.Error("another user's revoke ended this access token")
		}
	})

	t.Run("single session", func(t *testing.T) {
		_, rawSession, rawToken := revocationFixture(ctx, t, st)
		if err := st.RevokeSession(ctx, HashSecret(rawSession)); err != nil {
			t.Fatal(err)
		}
		assertRevoked(ctx, t, st, rawSession, rawToken)
	})

	t.Run("all sessions", func(t *testing.T) {
		userID, rawSession, rawToken := revocationFixture(ctx, t, st)
		if err := st.RevokeAllSessions(ctx, userID); err != nil {
			t.Fatal(err)
		}
		assertRevoked(ctx, t, st, rawSession, rawToken)
	})

	t.Run("scheduled deletion", func(t *testing.T) {
		userID, rawSession, rawToken := revocationFixture(ctx, t, st)
		if err := st.ScheduleDeletion(ctx, userID, time.Now().UTC().Add(72*time.Hour)); err != nil {
			t.Fatal(err)
		}
		assertRevoked(ctx, t, st, rawSession, rawToken)
	})
}
