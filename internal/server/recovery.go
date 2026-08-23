package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

func (a *App) recoveryPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, 200, "recover", map[string]any{"Title": "Recover", "Sent": r.URL.Query().Get("sent") != "" || r.URL.Query().Get("pending") != ""})
}

func (a *App) recoveryRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	_ = r.ParseForm()
	normalized, err := normalizeEmail(r.Form.Get("email"))
	if err == nil && a.EmailLimiter.Allow("recover:"+clientIP(r)) {
		user, findErr := a.Store.UserByNormalizedEmail(r.Context(), normalized)
		if findErr == nil && user.Status == "active" && user.Email != nil {
			token, tokenErr := security.RandomToken(32)
			if tokenErr == nil {
				_, storeErr := a.Store.StartRecoveryRequest(r.Context(), user.ID, store.HashSecret(token), time.Now().Add(time.Hour))
				if storeErr == nil {
					link := a.Config.Issuer + "/recover/complete?token=" + url.QueryEscape(token)
					sendAsync(r.Context(), func(ctx context.Context) error {
						return a.Mailer.Send(ctx, *user.Email, "Recover your Claustra account", "Open this one-time link within one hour to create a replacement passkey:\n\n"+link+"\n\nThe replacement will be quarantined for 24 hours. Existing passkeys can cancel it.")
					}, a.Logger.Error)
				}
			}
		}
	}
	http.Redirect(w, r, "/recover?sent=1", http.StatusSeeOther)
}

func (a *App) recoveryCompletePage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing recovery token", 400)
		return
	}
	if _, _, err := a.Store.PeekEmailToken(r.Context(), store.HashSecret(token), "recovery"); err != nil {
		http.Error(w, "recovery link is invalid or expired", 400)
		return
	}
	a.render(w, 200, "passkey", map[string]any{"Title": "Recovery", "Heading": "Create replacement passkey", "Description": "The replacement will be quarantined for 24 hours. Existing passkeys can cancel this recovery.", "Button": "Create replacement passkey", "Begin": "/webauthn/recovery/begin", "Finish": "/webauthn/recovery/finish", "Method": "create", "Continue": "/recover?pending=1", "Bootstrap": token})
}
func (a *App) recoveryComplete(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "use the passkey ceremony", http.StatusMethodNotAllowed)
}

func (a *App) recoveryBegin(w http.ResponseWriter, r *http.Request) {
	if !a.AuthLimiter.Allow("recovery-passkey:" + clientIP(r)) {
		writeJSON(w, 429, map[string]string{"error": "too many attempts"})
		return
	}
	var input ceremonyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil || input.Bootstrap == "" {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	tokenHash := store.HashSecret(input.Bootstrap)
	userID, recoveryIDText, err := a.Store.PeekEmailToken(r.Context(), tokenHash, "recovery")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "recovery link is invalid or expired"})
		return
	}
	user, err := a.Store.UserByID(r.Context(), userID)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "account unavailable"})
		return
	}
	creation, sessionData, err := a.WebAuthn.BeginRegistration(user)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	txToken, _ := security.RandomToken(32)
	sessionJSON, _ := json.Marshal(sessionData)
	continuationJSON, _ := json.Marshal(ceremonyContinuation{Continue: "/recover?pending=1", BootstrapHash: tokenHash})
	challenge := store.Challenge{Hash: store.HashSecret(txToken), Operation: "recovery", TransactionID: recoveryIDText, UserID: &userID, UserHandle: user.WebAuthnHandle, SessionData: sessionJSON, Continuation: continuationJSON, ExpiresAt: challengeExpiry(sessionData.Expires)}
	if err = a.Store.PutChallenge(r.Context(), challenge); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	writeJSON(w, 200, map[string]any{"options": creation, "transaction": txToken})
}

func (a *App) recoveryFinish(w http.ResponseWriter, r *http.Request) {
	challenge, err := a.Store.ConsumeChallenge(r.Context(), store.HashSecret(r.URL.Query().Get("transaction")), "recovery")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "challenge expired or already used"})
		return
	}
	if challenge.UserID == nil {
		writeJSON(w, 500, map[string]string{"error": "invalid recovery"})
		return
	}
	user, err := a.Store.UserByID(r.Context(), *challenge.UserID)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "account unavailable"})
		return
	}
	var sessionData webauthn.SessionData
	if err = json.Unmarshal(challenge.SessionData, &sessionData); err != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid stored challenge"})
		return
	}
	credential, err := a.WebAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "passkey registration was not valid"})
		return
	}
	var continuation ceremonyContinuation
	_ = json.Unmarshal(challenge.Continuation, &continuation)
	recoveryID, err := uuid.Parse(challenge.TransactionID)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid recovery"})
		return
	}
	if _, err = a.Store.BeginRecoveryQuarantine(r.Context(), recoveryID, user.ID, continuation.BootstrapHash, *credential, "Recovery passkey", a.Config.RecoveryDelay); err != nil {
		writeJSON(w, 400, map[string]string{"error": "recovery link is invalid or already used"})
		return
	}
	if user.Email != nil {
		sendAsync(r.Context(), func(ctx context.Context) error {
			return a.Mailer.Send(ctx, *user.Email, "Claustra recovery pending", "A replacement passkey was created. It will activate in 24 hours and revoke older passkeys. Sign in with an existing passkey to cancel recovery if this was not you.")
		}, a.Logger.Error)
	}
	a.Store.Audit(r.Context(), "recovery.quarantine_started", nil, &user.ID, nil, clientIP(r), r.UserAgent(), map[string]any{"completes_in": a.Config.RecoveryDelay.String()})
	writeJSON(w, 201, map[string]any{"redirect": "/recover?pending=1"})
}

func (a *App) recoveryCancel(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "account", r.Form.Get("csrf")) || !a.requireRecent(w, r, session) {
		return
	}
	id, err := uuid.Parse(r.Form.Get("recovery_id"))
	if err != nil {
		http.Error(w, "invalid recovery", 400)
		return
	}
	if err = a.Store.CancelRecovery(r.Context(), session.User.ID, id); err != nil {
		http.Error(w, "recovery not found", 404)
		return
	}
	a.Store.Audit(r.Context(), "recovery.cancelled", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), nil)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
