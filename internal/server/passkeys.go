package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

func (a *App) addPasskeyPage(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.requireRecent(w, r, session) {
		return
	}
	a.render(w, 200, "passkey", map[string]any{"Title": "Add passkey", "SignedIn": true, "Admin": session.Admin, "Heading": "Add another passkey", "Description": "Register another device or security key for this account.", "Button": "Add passkey", "Begin": "/webauthn/passkey/begin", "Finish": "/webauthn/passkey/finish", "Method": "create", "Continue": "/account"})
}
func (a *App) addPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.requireRecent(w, r, session) {
		return
	}
	creation, data, err := a.WebAuthn.BeginRegistration(session.User)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	raw, _ := security.RandomToken(32)
	sessionJSON, _ := json.Marshal(data)
	continuation, _ := json.Marshal(ceremonyContinuation{Continue: "/account"})
	uid := session.User.ID
	if err = a.Store.PutChallenge(r.Context(), store.Challenge{Hash: store.HashSecret(raw), Operation: "add_passkey", TransactionID: base64.RawURLEncoding.EncodeToString(session.Session.Hash), UserID: &uid, UserHandle: session.User.WebAuthnHandle, SessionData: sessionJSON, Continuation: continuation, ExpiresAt: challengeExpiry(data.Expires)}); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	writeJSON(w, 200, map[string]any{"options": creation, "transaction": raw})
}
func (a *App) addPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.requireRecent(w, r, session) {
		return
	}
	challenge, err := a.Store.ConsumeChallenge(r.Context(), store.HashSecret(r.URL.Query().Get("transaction")), "add_passkey")
	if err != nil || challenge.UserID == nil || *challenge.UserID != session.User.ID {
		writeJSON(w, 400, map[string]string{"error": "challenge invalid or expired"})
		return
	}
	var data webauthn.SessionData
	if err = json.Unmarshal(challenge.SessionData, &data); err != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid challenge"})
		return
	}
	credential, err := a.WebAuthn.FinishRegistration(session.User, data, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "passkey registration was not valid"})
		return
	}
	id, err := a.Store.AddCredential(r.Context(), session.User.ID, *credential, "Passkey", "active")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not add passkey"})
		return
	}
	a.Store.Audit(r.Context(), "credential.added", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), map[string]any{"credential_id": id})
	writeJSON(w, 201, map[string]any{"redirect": "/account"})
}
func (a *App) revokePasskey(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "account", r.Form.Get("csrf")) || !a.requireRecent(w, r, session) {
		return
	}
	id, err := uuid.Parse(r.Form.Get("credential_id"))
	if err != nil {
		http.Error(w, "invalid passkey", 400)
		return
	}
	if err = a.Store.RevokeCredential(r.Context(), session.User.ID, id); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.Store.Audit(r.Context(), "credential.revoked", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), map[string]any{"credential_id": id})
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
func (a *App) revokeAccountSession(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "account", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	hash, err := base64.RawURLEncoding.DecodeString(r.Form.Get("session"))
	if err != nil {
		http.Error(w, "invalid session", 400)
		return
	}
	_ = a.Store.RevokeOwnedSession(r.Context(), session.User.ID, hash)
	if string(hash) == string(session.Session.Hash) {
		a.clearSessionCookie(w)
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
func (a *App) revokeConsent(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "account", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	clientID := r.Form.Get("client_id")
	if err := a.Store.RevokeConsent(r.Context(), session.User.ID, clientID); err != nil {
		http.Error(w, "could not revoke access", 500)
		return
	}
	a.Store.Audit(r.Context(), "consent.revoked", &session.User.ID, &session.User.ID, &clientID, clientIP(r), r.UserAgent(), nil)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
