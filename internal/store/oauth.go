package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type AuthorizationCode struct {
	Hash          []byte
	UserID        uuid.UUID
	ClientID      string
	RedirectURI   string
	PKCEChallenge string
	Nonce         string
	Scopes        []string
	AuthTime      time.Time
	ExpiresAt     time.Time
}

type AccessToken struct {
	Hash        []byte
	UserID      uuid.UUID
	ClientID    string
	SessionHash []byte
	Scopes      []string
	ExpiresAt   time.Time
}

func (s *Store) ClientByID(ctx context.Context, id string) (Client, error) {
	var c Client
	err := s.Pool.QueryRow(ctx, `SELECT id,name,COALESCE(logo_uri,''),COALESCE(homepage_uri,''),COALESCE(privacy_policy_uri,''),trusted,enabled FROM clients WHERE id=$1`, id).Scan(&c.ID, &c.Name, &c.LogoURI, &c.HomepageURI, &c.PrivacyPolicyURI, &c.Trusted, &c.Enabled)
	if err != nil {
		return Client{}, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT redirect_uri FROM client_redirect_uris WHERE client_id=$1 ORDER BY redirect_uri`, id)
	if err != nil {
		return Client{}, err
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return Client{}, err
		}
		c.RedirectURIs = append(c.RedirectURIs, v)
	}
	rows.Close()
	rows, err = s.Pool.Query(ctx, `SELECT scope,preapproved FROM client_scopes WHERE client_id=$1 ORDER BY scope`, id)
	if err != nil {
		return Client{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var scope string
		var pre bool
		if err := rows.Scan(&scope, &pre); err != nil {
			return Client{}, err
		}
		c.AllowedScopes = append(c.AllowedScopes, scope)
		if pre {
			c.PreapprovedScopes = append(c.PreapprovedScopes, scope)
		}
	}
	return c, rows.Err()
}

func (c Client) AllowsRedirect(redirect string) bool {
	for _, v := range c.RedirectURIs {
		if subtle.ConstantTimeCompare([]byte(v), []byte(redirect)) == 1 {
			return true
		}
	}
	return false
}
func (c Client) AllowsScopes(scopes []string) bool {
	allowed := map[string]bool{}
	for _, s := range c.AllowedScopes {
		allowed[s] = true
	}
	for _, scope := range scopes {
		if !allowed[scope] {
			return false
		}
	}
	return true
}
func (c Client) Preapproves(scopes []string) bool {
	allowed := map[string]bool{}
	for _, s := range c.PreapprovedScopes {
		allowed[s] = true
	}
	for _, scope := range scopes {
		if !allowed[scope] {
			return false
		}
	}
	return true
}

type NewClient struct {
	Client
	SecretHash []byte
	CreatedBy  uuid.UUID
}

func (s *Store) CreateClient(ctx context.Context, input NewClient) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO clients(id,name,logo_uri,homepage_uri,privacy_policy_uri,trusted,created_by) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),$6,$7)`, input.ID, input.Name, input.LogoURI, input.HomepageURI, input.PrivacyPolicyURI, input.Trusted, input.CreatedBy)
	if err != nil {
		return uuid.Nil, err
	}
	for _, redirect := range input.RedirectURIs {
		if _, err = tx.Exec(ctx, `INSERT INTO client_redirect_uris(client_id,redirect_uri) VALUES($1,$2)`, input.ID, redirect); err != nil {
			return uuid.Nil, err
		}
	}
	pre := map[string]bool{}
	for _, v := range input.PreapprovedScopes {
		pre[v] = true
	}
	for _, scope := range input.AllowedScopes {
		if _, err = tx.Exec(ctx, `INSERT INTO client_scopes(client_id,scope,preapproved) VALUES($1,$2,$3)`, input.ID, scope, pre[scope]); err != nil {
			return uuid.Nil, err
		}
	}
	secretID := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO client_secrets(id,client_id,secret_hash) VALUES($1,$2,$3)`, secretID, input.ID, input.SecretHash)
	if err != nil {
		return uuid.Nil, err
	}
	return secretID, tx.Commit(ctx)
}

func (s *Store) ValidateClientSecret(ctx context.Context, clientID, secret string) bool {
	rows, err := s.Pool.Query(ctx, `SELECT cs.secret_hash FROM client_secrets cs JOIN clients c ON c.id=cs.client_id WHERE cs.client_id=$1 AND c.enabled=true AND cs.revoked_at IS NULL AND (cs.expires_at IS NULL OR cs.expires_at>now())`, clientID)
	if err != nil {
		return false
	}
	defer rows.Close()
	hash := HashSecret(secret)
	for rows.Next() {
		var candidate []byte
		if rows.Scan(&candidate) == nil && subtle.ConstantTimeCompare(hash, candidate) == 1 {
			return true
		}
	}
	return false
}

func NormalizeScopes(value string) ([]string, error) {
	set := map[string]bool{}
	for _, scope := range strings.Fields(value) {
		switch scope {
		case "openid", "profile", "email":
			set[scope] = true
		default:
			return nil, errors.New("unsupported scope")
		}
	}
	if !set["openid"] {
		return nil, errors.New("openid scope is required")
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func ValidHTTPSURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func (s *Store) ConsentCovers(ctx context.Context, userID uuid.UUID, client Client, scopes []string) (bool, error) {
	if client.Trusted && client.Preapproves(scopes) {
		return true, nil
	}
	var granted []string
	err := s.Pool.QueryRow(ctx, `SELECT scopes FROM consents WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NULL`, userID, client.ID).Scan(&granted)
	if IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	set := map[string]bool{}
	for _, v := range granted {
		set[v] = true
	}
	for _, v := range scopes {
		if !set[v] {
			return false, nil
		}
	}
	return true, nil
}

func (s *Store) GrantConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO consents(user_id,client_id,scopes) VALUES($1,$2,$3) ON CONFLICT(user_id,client_id) DO UPDATE SET scopes=(SELECT ARRAY(SELECT DISTINCT unnest(consents.scopes||excluded.scopes) ORDER BY 1)),updated_at=now(),revoked_at=NULL`, userID, clientID, scopes)
	return err
}

func (s *Store) PairwiseSubject(ctx context.Context, userID uuid.UUID, clientID string) (string, error) {
	var subject string
	err := s.Pool.QueryRow(ctx, `SELECT subject FROM pairwise_subjects WHERE user_id=$1 AND client_id=$2`, userID, clientID).Scan(&subject)
	if err == nil {
		return subject, nil
	}
	if !IsNotFound(err) {
		return "", err
	}
	subject = uuid.NewString()
	err = s.Pool.QueryRow(ctx, `INSERT INTO pairwise_subjects(user_id,client_id,subject) VALUES($1,$2,$3) ON CONFLICT(user_id,client_id) DO UPDATE SET user_id=excluded.user_id RETURNING subject`, userID, clientID, subject).Scan(&subject)
	return subject, err
}

func (s *Store) PutAuthorizationCode(ctx context.Context, c AuthorizationCode) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO authorization_codes(code_hash,user_id,client_id,redirect_uri,pkce_challenge,nonce,scopes,auth_time,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.Hash, c.UserID, c.ClientID, c.RedirectURI, c.PKCEChallenge, c.Nonce, c.Scopes, c.AuthTime, c.ExpiresAt)
	return err
}

func (s *Store) ConsumeAuthorizationCode(ctx context.Context, hash []byte) (AuthorizationCode, error) {
	var c AuthorizationCode
	err := s.Pool.QueryRow(ctx, `UPDATE authorization_codes SET used_at=now() WHERE code_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING code_hash,user_id,client_id,redirect_uri,pkce_challenge,nonce,scopes,auth_time,expires_at`, hash).Scan(&c.Hash, &c.UserID, &c.ClientID, &c.RedirectURI, &c.PKCEChallenge, &c.Nonce, &c.Scopes, &c.AuthTime, &c.ExpiresAt)
	return c, err
}

func (s *Store) PutAccessToken(ctx context.Context, t AccessToken) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO access_tokens(token_hash,user_id,client_id,session_hash,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, t.Hash, t.UserID, t.ClientID, t.SessionHash, t.Scopes, t.ExpiresAt)
	return err
}

func (s *Store) AccessTokenByRaw(ctx context.Context, raw string) (AccessToken, error) {
	var t AccessToken
	err := s.Pool.QueryRow(ctx, `SELECT token_hash,user_id,client_id,COALESCE(session_hash,'\\x'::bytea),scopes,expires_at FROM access_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now()`, HashSecret(raw)).Scan(&t.Hash, &t.UserID, &t.ClientID, &t.SessionHash, &t.Scopes, &t.ExpiresAt)
	return t, err
}

func (s *Store) RevokeAccessToken(ctx context.Context, raw string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE access_tokens SET revoked_at=now() WHERE token_hash=$1`, HashSecret(raw))
	return err
}

func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM clients ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	clients := make([]Client, 0, len(ids))
	for _, id := range ids {
		c, err := s.ClientByID(ctx, id)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, nil
}
