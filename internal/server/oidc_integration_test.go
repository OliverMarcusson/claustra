package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/olivermarcusson/claustra/internal/config"
	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

// This covers the token exchange and UserInfo, not access control, so its
// client is explicitly open. Clients default to admitting nobody, and the
// allowlist is exercised in access_integration_test.go instead.
func TestAuthorizationCodeTokenExchange(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Config: config.Config{Issuer: "https://claustra.example", AccessTokenTTL: 15 * time.Minute, IDTokenTTL: 5 * time.Minute}, Store: st, SigningKey: key, SigningKeyID: "test-key"}
	user := store.User{ID: uuid.New(), WebAuthnHandle: []byte(uuid.NewString()), Status: "active", CreatedAt: time.Now().UTC()}
	credential := webauthn.Credential{ID: []byte(uuid.NewString()), PublicKey: []byte("public")}
	if _, _, err = st.CreateUserWithCredential(ctx, user, credential, "Test", nil); err != nil {
		t.Fatal(err)
	}
	clientID := "oidc-" + uuid.NewString()[:8]
	clientSecret := "client-secret-" + uuid.NewString()
	redirectURI := "https://client.example/callback"
	if _, err = st.CreateClient(ctx, store.NewClient{Client: store.Client{ID: clientID, Name: "OIDC Test", AccessPolicy: store.AccessOpen, RedirectURIs: []string{redirectURI}, AllowedScopes: []string{"openid", "profile"}}, SecretHash: store.HashSecret(clientSecret), CreatedBy: user.ID}); err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	rawCode := "code-" + uuid.NewString()
	now := time.Now().UTC()
	if err = st.PutAuthorizationCode(ctx, store.AuthorizationCode{Hash: store.HashSecret(rawCode), UserID: user.ID, ClientID: clientID, RedirectURI: redirectURI, PKCEChallenge: security.PKCEChallenge(verifier), Nonce: "test-nonce", Scopes: []string{"openid"}, AuthTime: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {rawCode}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	request := httptest.NewRequest(http.MethodPost, "https://claustra.example/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)
	response := httptest.NewRecorder()
	app.token(response, request)
	if response.Code != 200 {
		t.Fatalf("token status %d: %s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err = json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	idToken, _ := payload["id_token"].(string)
	parsed, err := jwt.Parse(idToken, func(token *jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithAudience(clientID), jwt.WithIssuer(app.Config.Issuer), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("invalid ID token: %v", err)
	}
	access, _ := payload["access_token"].(string)
	request = httptest.NewRequest(http.MethodGet, "https://claustra.example/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+access)
	response = httptest.NewRecorder()
	app.userinfo(response, request)
	if response.Code != 200 {
		t.Fatalf("userinfo status %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"sub"`) {
		t.Fatal("userinfo has no subject")
	}
}
