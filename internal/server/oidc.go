package server

import (
	"crypto/subtle"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

type authorizationRequest struct {
	ClientID, RedirectURI, Scope, State, Nonce, CodeChallenge, CodeChallengeMethod string
	// Prompt and MaxAge drive step-up authentication. They are deliberately
	// absent from fields(): those values round-trip through the consent form,
	// and a prompt=login that survived the round trip would demand the
	// ceremony again on the way back from the consent the user just gave.
	Prompt string
	MaxAge string
}

func parseAuthorizationRequest(values url.Values) authorizationRequest {
	return authorizationRequest{ClientID: values.Get("client_id"), RedirectURI: values.Get("redirect_uri"), Scope: values.Get("scope"), State: values.Get("state"), Nonce: values.Get("nonce"), CodeChallenge: values.Get("code_challenge"), CodeChallengeMethod: values.Get("code_challenge_method"), Prompt: values.Get("prompt"), MaxAge: values.Get("max_age")}
}

// maxAgeSeconds reports the freshness the client asked for. The second result
// is false when no max_age was sent, which is not the same as max_age=0: zero
// means "authenticate now", absent means "any live session will do".
func (q authorizationRequest) maxAgeSeconds() (int, bool, bool) {
	if q.MaxAge == "" {
		return 0, false, true
	}
	seconds, err := strconv.Atoi(q.MaxAge)
	if err != nil || seconds < 0 {
		return 0, false, false
	}
	return seconds, true, true
}

// promptValues splits the space-delimited prompt parameter.
func (q authorizationRequest) promptValues() []string { return strings.Fields(q.Prompt) }

func (q authorizationRequest) hasPrompt(value string) bool {
	for _, v := range q.promptValues() {
		if v == value {
			return true
		}
	}
	return false
}

// staleAuth reports whether the session is older than this request will accept.
//
// max_age=0 means "authenticate now" and can never be satisfied by an existing
// session, so it always demands the ceremony; stepUp drops it from the
// continuation to keep that one-shot rather than a loop. Larger values compare
// in whole seconds, so the ceremony that just ran satisfies them on the way
// back without any special handling.
func (q authorizationRequest) staleAuth(authTime time.Time) bool {
	seconds, present, _ := q.maxAgeSeconds()
	if !present {
		return false
	}
	if seconds == 0 {
		return true
	}
	return int(time.Since(authTime).Seconds()) > seconds
}

// oneShotStepUp reports whether a parameter forces the ceremony every time it
// is seen, and so must not survive into the continuation.
func (q authorizationRequest) oneShotMaxAge() bool {
	seconds, present, _ := q.maxAgeSeconds()
	return present && seconds == 0
}
func (q authorizationRequest) fields() map[string]string {
	return map[string]string{"client_id": q.ClientID, "redirect_uri": q.RedirectURI, "scope": q.Scope, "state": q.State, "nonce": q.Nonce, "code_challenge": q.CodeChallenge, "code_challenge_method": q.CodeChallengeMethod, "response_type": "code"}
}
func (q authorizationRequest) values() url.Values {
	v := url.Values{}
	for k, x := range q.fields() {
		v.Set(k, x)
	}
	return v
}

func (a *App) validateAuthorization(r *http.Request, q authorizationRequest) (store.Client, []string, string) {
	if q.ClientID == "" || q.RedirectURI == "" {
		return store.Client{}, nil, "invalid_request"
	}
	client, err := a.Store.ClientByID(r.Context(), q.ClientID)
	if err != nil || !client.Enabled {
		return store.Client{}, nil, "unauthorized_client"
	}
	if !client.AllowsRedirect(q.RedirectURI) {
		return store.Client{}, nil, "invalid_redirect_uri"
	}
	if r.FormValue("response_type") != "code" {
		return client, nil, "unsupported_response_type"
	}
	scopes, err := store.NormalizeScopes(q.Scope)
	if err != nil || !client.AllowsScopes(scopes) {
		return client, nil, "invalid_scope"
	}
	if q.State == "" || q.Nonce == "" || q.CodeChallenge == "" || q.CodeChallengeMethod != "S256" {
		return client, nil, "invalid_request"
	}
	if len(q.CodeChallenge) < 43 || len(q.CodeChallenge) > 128 {
		return client, nil, "invalid_request"
	}
	if _, _, ok := q.maxAgeSeconds(); !ok {
		return client, nil, "invalid_request"
	}
	for _, value := range q.promptValues() {
		switch value {
		case "none", "login", "consent":
		default:
			return client, nil, "invalid_request"
		}
	}
	// "none" means never show the user anything, so pairing it with a value
	// whose whole job is to show the user something is a contradiction.
	if q.hasPrompt("none") && len(q.promptValues()) > 1 {
		return client, nil, "invalid_request"
	}
	return client, scopes, ""
}

func (a *App) authorize(w http.ResponseWriter, r *http.Request) {
	q := parseAuthorizationRequest(r.URL.Query())
	client, scopes, code := a.validateAuthorization(r, q)
	if code != "" {
		if client.ID != "" && client.AllowsRedirect(q.RedirectURI) {
			redirectOAuthError(w, r, q.RedirectURI, q.State, code)
		} else {
			http.Error(w, "invalid authorization request", http.StatusBadRequest)
		}
		return
	}
	session, err := a.currentSession(r)
	if err != nil {
		if q.hasPrompt("none") {
			redirectOAuthError(w, r, q.RedirectURI, q.State, "login_required")
			return
		}
		http.Redirect(w, r, "/login?continue="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	if q.hasPrompt("login") || q.staleAuth(session.Session.AuthTime) {
		if q.hasPrompt("none") {
			redirectOAuthError(w, r, q.RedirectURI, q.State, "login_required")
			return
		}
		a.stepUp(w, r, session, q)
		return
	}
	if !a.permitClient(w, r, session, client) {
		return
	}
	covered, err := a.Store.ConsentCovers(r.Context(), session.User.ID, client, scopes)
	if err != nil {
		http.Error(w, "authorization failed", 500)
		return
	}
	if q.hasPrompt("consent") {
		covered = false
	}
	if !covered && q.hasPrompt("none") {
		redirectOAuthError(w, r, q.RedirectURI, q.State, "consent_required")
		return
	}
	if !covered {
		a.render(w, http.StatusOK, "consent", map[string]any{"Title": "Authorize", "SignedIn": true, "Admin": session.Admin, "LogoutCSRF": security.CSRF(session.RawToken, "account"), "Client": client, "Scopes": scopes, "Fields": q.fields(), "CSRF": security.CSRF(session.RawToken, "consent")})
		return
	}
	a.issueAuthorizationCode(w, r, session, q, scopes)
}

func (a *App) authorizeConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !security.ValidateCSRF(session.RawToken, "consent", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	q := parseAuthorizationRequest(r.Form)
	client, scopes, code := a.validateAuthorization(r, q)
	if code != "" {
		http.Error(w, "invalid authorization request", 400)
		return
	}
	if r.Form.Get("decision") != "allow" {
		redirectOAuthError(w, r, q.RedirectURI, q.State, "access_denied")
		return
	}
	if !a.permitClient(w, r, session, client) {
		return
	}
	if err := a.Store.GrantConsent(r.Context(), session.User.ID, client.ID, scopes); err != nil {
		http.Error(w, "could not store consent", 500)
		return
	}
	a.Store.Audit(r.Context(), "consent.granted", &session.User.ID, &session.User.ID, &client.ID, clientIP(r), r.UserAgent(), map[string]any{"scopes": scopes})
	a.issueAuthorizationCode(w, r, session, q, scopes)
}

func (a *App) issueAuthorizationCode(w http.ResponseWriter, r *http.Request, session sessionContext, q authorizationRequest, scopes []string) {
	raw, err := security.RandomToken(32)
	if err != nil {
		http.Error(w, "authorization failed", 500)
		return
	}
	now := time.Now().UTC()
	code := store.AuthorizationCode{Hash: store.HashSecret(raw), UserID: session.User.ID, ClientID: q.ClientID, RedirectURI: q.RedirectURI, PKCEChallenge: q.CodeChallenge, Nonce: q.Nonce, Scopes: scopes, AuthTime: session.Session.AuthTime, ExpiresAt: now.Add(a.Config.CodeTTL)}
	if err = a.Store.PutAuthorizationCode(r.Context(), code); err != nil {
		http.Error(w, "authorization failed", 500)
		return
	}
	target, _ := url.Parse(q.RedirectURI)
	values := target.Query()
	values.Set("code", raw)
	values.Set("state", q.State)
	target.RawQuery = values.Encode()
	a.Store.Audit(r.Context(), "authorization.issued", &session.User.ID, &session.User.ID, &q.ClientID, clientIP(r), r.UserAgent(), map[string]any{"scopes": scopes})
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirect, state, code string) {
	target, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	q := target.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (a *App) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "invalid form")
		return
	}
	clientID, secret, ok := r.BasicAuth()
	if !ok || !a.Store.ValidateClientSecret(r.Context(), clientID, secret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="claustra-token"`)
		oauthError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		oauthError(w, 400, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	codeRaw := r.Form.Get("code")
	verifier := r.Form.Get("code_verifier")
	if codeRaw == "" || verifier == "" {
		oauthError(w, 400, "invalid_request", "code and code_verifier are required")
		return
	}
	code, err := a.Store.ConsumeAuthorizationCode(r.Context(), store.HashSecret(codeRaw))
	if err != nil {
		oauthError(w, 400, "invalid_grant", "code is invalid, expired, or used")
		return
	}
	if subtle.ConstantTimeCompare([]byte(code.ClientID), []byte(clientID)) != 1 || subtle.ConstantTimeCompare([]byte(code.RedirectURI), []byte(r.Form.Get("redirect_uri"))) != 1 || subtle.ConstantTimeCompare([]byte(code.PKCEChallenge), []byte(security.PKCEChallenge(verifier))) != 1 {
		oauthError(w, 400, "invalid_grant", "code binding failed")
		return
	}
	user, err := a.Store.UserByID(r.Context(), code.UserID)
	if err != nil {
		oauthError(w, 400, "invalid_grant", "account unavailable")
		return
	}
	// Re-check the allowlist at redemption. The code was issued against the
	// policy as it stood at /authorize, and without this an address removed in
	// the seconds since would still buy a full-lifetime access token.
	allowed, err := a.Store.ClientAccessAllowed(r.Context(), clientID, user.ID)
	if err != nil {
		oauthError(w, 500, "server_error", "could not issue token")
		return
	}
	if !allowed {
		oauthError(w, 400, "invalid_grant", "account may not use this client")
		return
	}
	subject, err := a.Store.PairwiseSubject(r.Context(), user.ID, clientID)
	if err != nil {
		oauthError(w, 500, "server_error", "could not issue token")
		return
	}
	accessRaw, err := security.RandomToken(32)
	if err != nil {
		oauthError(w, 500, "server_error", "could not issue token")
		return
	}
	now := time.Now().UTC()
	access := store.AccessToken{Hash: store.HashSecret(accessRaw), UserID: user.ID, ClientID: clientID, Scopes: code.Scopes, ExpiresAt: now.Add(a.Config.AccessTokenTTL)}
	if err = a.Store.PutAccessToken(r.Context(), access); err != nil {
		oauthError(w, 500, "server_error", "could not issue token")
		return
	}
	claims := jwt.MapClaims{"iss": a.Config.Issuer, "sub": subject, "aud": clientID, "iat": now.Unix(), "exp": now.Add(a.Config.IDTokenTTL).Unix(), "auth_time": code.AuthTime.Unix(), "nonce": code.Nonce}
	id := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	id.Header["kid"] = a.SigningKeyID
	idRaw, err := id.SignedString(a.SigningKey)
	if err != nil {
		oauthError(w, 500, "server_error", "could not sign token")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, 200, map[string]any{"access_token": accessRaw, "token_type": "Bearer", "expires_in": int(a.Config.AccessTokenTTL.Seconds()), "id_token": idRaw, "scope": formScopes(code.Scopes)})
}

func bearerToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}
func (a *App) userinfo(w http.ResponseWriter, r *http.Request) {
	token, err := a.Store.AccessTokenByRaw(r.Context(), bearerToken(r))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, 401, "invalid_token", "token is invalid or expired")
		return
	}
	user, err := a.Store.UserByID(r.Context(), token.UserID)
	if err != nil {
		oauthError(w, 401, "invalid_token", "account unavailable")
		return
	}
	subject, err := a.Store.PairwiseSubject(r.Context(), user.ID, token.ClientID)
	if err != nil {
		oauthError(w, 500, "server_error", "could not load subject")
		return
	}
	claims := map[string]any{"sub": subject}
	if hasScope(token.Scopes, "profile") {
		if user.DisplayName != nil {
			claims["name"] = *user.DisplayName
		}
		if a.Store.HasAvatar(r.Context(), user.ID) {
			claims["picture"] = a.Config.Issuer + "/avatar"
		}
	}
	if hasScope(token.Scopes, "email") && user.EmailVerified && user.Email != nil {
		claims["email"] = *user.Email
		claims["email_verified"] = true
	}
	writeJSON(w, 200, claims)
}

func (a *App) avatar(w http.ResponseWriter, r *http.Request) {
	token, err := a.Store.AccessTokenByRaw(r.Context(), bearerToken(r))
	if err != nil || !hasScope(token.Scopes, "profile") {
		http.Error(w, "unauthorized", 401)
		return
	}
	media, image, version, err := a.Store.Avatar(r.Context(), token.UserID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("ETag", `"`+version.String()+`"`)
	_, _ = w.Write(image)
}

func (a *App) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID, secret, ok := r.BasicAuth()
	if !ok || !a.Store.ValidateClientSecret(r.Context(), clientID, secret) {
		oauthError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	_ = a.Store.RevokeTokenForClient(r.Context(), r.Form.Get("token"), clientID)
	w.WriteHeader(http.StatusOK)
}

func (a *App) discovery(w http.ResponseWriter, r *http.Request) {
	issuer := a.Config.Issuer
	writeJSON(w, 200, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "userinfo_endpoint": issuer + "/userinfo", "jwks_uri": issuer + "/jwks.json", "revocation_endpoint": issuer + "/revoke", "response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"}, "subject_types_supported": []string{"pairwise"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "scopes_supported": []string{"openid", "profile", "email"}, "claims_supported": []string{"sub", "name", "picture", "email", "email_verified", "iss", "aud", "exp", "iat", "auth_time", "nonce"}, "grant_types_supported": []string{"authorization_code"}, "prompt_values_supported": []string{"none", "login", "consent"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}})
}
func (a *App) oauthMetadata(w http.ResponseWriter, r *http.Request) { a.discovery(w, r) }

func (a *App) jwks(w http.ResponseWriter, r *http.Request) {
	pub := a.SigningKey.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	keys := []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": a.SigningKeyID, "n": n, "e": e}}
	for _, previous := range a.PreviousSigningKeys {
		keys = append(keys, map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": previous.KeyID, "n": base64.RawURLEncoding.EncodeToString(previous.Key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(previous.Key.E)).Bytes())})
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, 200, map[string]any{"keys": keys})
}
