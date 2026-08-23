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

func (a *App) deleteAccount(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "account", r.Form.Get("csrf")) || !a.requireRecent(w, r, session) {
		return
	}
	if session.Admin && a.Store.IsLastAdmin(r.Context(), session.User.ID) {
		http.Error(w, "promote another administrator before deleting the final administrator account", 400)
		return
	}
	due := time.Now().Add(a.Config.DeleteGrace)
	if err := a.Store.ScheduleDeletion(r.Context(), session.User.ID, due); err != nil {
		http.Error(w, "could not schedule deletion", 500)
		return
	}
	if session.User.EmailVerified && session.User.Email != nil {
		token, _ := security.RandomToken(32)
		if err := a.Store.PutEmailToken(r.Context(), session.User.ID, "delete_cancel", "", store.HashSecret(token), due); err == nil {
			link := a.Config.Issuer + "/delete/cancel/email?token=" + url.QueryEscape(token)
			sendAsync(r.Context(), func(ctx context.Context) error {
				return a.Mailer.Send(ctx, *session.User.Email, "Claustra account deletion scheduled", "Your account is disabled and will be deleted after seven days. Cancel deletion here:\n\n"+link)
			}, a.Logger.Error)
		}
	}
	a.Store.Audit(r.Context(), "account.deletion_scheduled", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), map[string]any{"due": due})
	a.clearSessionCookie(w)
	a.render(w, 200, "message", map[string]any{"Title": "Deletion scheduled", "Heading": "Account disabled", "Message": "Your account will be permanently deleted after seven days. Use a registered passkey or the link sent to your verified email to cancel."})
}

func (a *App) deletionCancelPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, 200, "passkey", map[string]any{"Title": "Cancel deletion", "Heading": "Cancel account deletion", "Description": "Use an existing passkey before the seven-day grace period ends.", "Button": "Use passkey", "Begin": "/webauthn/delete-cancel/begin", "Finish": "/webauthn/delete-cancel/finish", "Method": "get", "Continue": "/account"})
}
func (a *App) deletionCancelEmail(w http.ResponseWriter, r *http.Request) {
	userID, _, err := a.Store.ConsumeEmailToken(r.Context(), store.HashSecret(r.URL.Query().Get("token")), "delete_cancel")
	if err != nil {
		http.Error(w, "cancellation link is invalid or expired", 400)
		return
	}
	if err = a.Store.CancelDeletion(r.Context(), userID); err != nil {
		http.Error(w, "could not restore account", 400)
		return
	}
	a.Store.Audit(r.Context(), "account.deletion_cancelled", &userID, &userID, nil, clientIP(r), r.UserAgent(), map[string]any{"method": "email"})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) deletionCancelBegin(w http.ResponseWriter, r *http.Request) {
	assertion, sessionData, err := a.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	txToken, _ := security.RandomToken(32)
	sessionJSON, _ := json.Marshal(sessionData)
	if err = a.Store.PutChallenge(r.Context(), store.Challenge{Hash: store.HashSecret(txToken), Operation: "delete_cancel", TransactionID: uuid.NewString(), SessionData: sessionJSON, Continuation: json.RawMessage(`{}`), ExpiresAt: sessionData.Expires}); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	writeJSON(w, 200, map[string]any{"options": assertion, "transaction": txToken})
}

func (a *App) deletionCancelFinish(w http.ResponseWriter, r *http.Request) {
	challenge, err := a.Store.ConsumeChallenge(r.Context(), store.HashSecret(r.URL.Query().Get("transaction")), "delete_cancel")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "challenge expired or already used"})
		return
	}
	var sessionData webauthn.SessionData
	if err = json.Unmarshal(challenge.SessionData, &sessionData); err != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid challenge"})
		return
	}
	userValue, credential, err := a.WebAuthn.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		user, err := a.Store.DiscoverableDeletionUser(r.Context(), rawID, userHandle)
		if err != nil {
			return nil, err
		}
		return user, nil
	}, sessionData, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "passkey assertion was not valid"})
		return
	}
	user := userValue.(store.WebAuthnUser)
	if err = a.Store.CancelDeletion(r.Context(), user.ID); err != nil {
		writeJSON(w, 400, map[string]string{"error": "could not restore account"})
		return
	}
	credentialID, err := a.Store.UpdateCredential(r.Context(), user.ID, *credential)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not update passkey"})
		return
	}
	raw, err := a.newSession(r, user.ID, &credentialID)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create session"})
		return
	}
	a.setSessionCookie(w, raw)
	a.Store.Audit(r.Context(), "account.deletion_cancelled", &user.ID, &user.ID, nil, clientIP(r), r.UserAgent(), map[string]any{"method": "passkey"})
	writeJSON(w, 200, map[string]any{"redirect": "/account"})
}
