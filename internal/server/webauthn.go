package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

type ceremonyRequest struct {
	Continue  string `json:"continue"`
	Bootstrap string `json:"bootstrap"`
}
type ceremonyContinuation struct {
	Continue      string `json:"continue"`
	BootstrapHash []byte `json:"bootstrap_hash,omitempty"`
}

func (a *App) registerPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, http.StatusOK, "passkey", map[string]any{"Title": "Create account", "Heading": "Create account", "Description": "Create a discoverable passkey. Profile information is optional and can be added later.", "Button": "Create passkey", "Begin": "/webauthn/register/begin", "Finish": "/webauthn/register/finish", "Method": "create", "Continue": safeContinuation(r.URL.Query().Get("continue")), "Bootstrap": r.URL.Query().Get("bootstrap")})
}
func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, http.StatusOK, "passkey", map[string]any{"Title": "Sign in", "Heading": "Sign in", "Description": "Use one of the passkeys registered with Claustra.", "Button": "Use passkey", "Begin": "/webauthn/login/begin", "Finish": "/webauthn/login/finish", "Method": "get", "Continue": safeContinuation(r.URL.Query().Get("continue"))})
}

func (a *App) registrationBegin(w http.ResponseWriter, r *http.Request) {
	if !a.AuthLimiter.Allow("register:" + clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts"})
		return
	}
	var input ceremonyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil && !errors.Is(err, http.ErrBodyReadAfterClose) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	handle, err := security.RandomBytes(64)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	user := store.WebAuthnUser{User: store.User{ID: uuid.New(), WebAuthnHandle: handle, Status: "active", CreatedAt: time.Now().UTC()}}
	creation, sessionData, err := a.WebAuthn.BeginRegistration(user)
	if err != nil {
		a.Logger.Error("begin registration", "error", err)
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	txToken, err := security.RandomToken(32)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	sessionJSON, _ := json.Marshal(sessionData)
	continuation := ceremonyContinuation{Continue: safeContinuation(input.Continue)}
	if input.Bootstrap != "" {
		continuation.BootstrapHash = store.HashSecret(input.Bootstrap)
	}
	continuationJSON, _ := json.Marshal(continuation)
	uid := user.ID
	challenge := store.Challenge{Hash: store.HashSecret(txToken), Operation: "register", TransactionID: uuid.NewString(), UserID: &uid, UserHandle: handle, SessionData: sessionJSON, Continuation: continuationJSON, ExpiresAt: challengeExpiry(sessionData.Expires)}
	if err := a.Store.PutChallenge(r.Context(), challenge); err != nil {
		a.Logger.Error("store registration challenge", "error", err)
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": creation, "transaction": txToken})
}

func (a *App) registrationFinish(w http.ResponseWriter, r *http.Request) {
	txToken := r.URL.Query().Get("transaction")
	if txToken == "" {
		writeJSON(w, 400, map[string]string{"error": "missing transaction"})
		return
	}
	challenge, err := a.Store.ConsumeChallenge(r.Context(), store.HashSecret(txToken), "register")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "challenge expired or already used"})
		return
	}
	var sessionData webauthn.SessionData
	if err = json.Unmarshal(challenge.SessionData, &sessionData); err != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid stored challenge"})
		return
	}
	var continuation ceremonyContinuation
	_ = json.Unmarshal(challenge.Continuation, &continuation)
	if challenge.UserID == nil {
		writeJSON(w, 500, map[string]string{"error": "invalid registration"})
		return
	}
	user := store.WebAuthnUser{User: store.User{ID: *challenge.UserID, WebAuthnHandle: challenge.UserHandle, Status: "active", CreatedAt: time.Now().UTC()}}
	credential, err := a.WebAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		a.Store.Audit(r.Context(), "registration.failed", nil, nil, nil, clientIP(r), r.UserAgent(), map[string]any{"reason": "webauthn_validation"})
		writeJSON(w, 400, map[string]string{"error": "passkey registration was not valid"})
		return
	}
	credentialID, becameAdmin, err := a.Store.CreateUserWithCredential(r.Context(), user.User, *credential, "Passkey", continuation.BootstrapHash)
	if err != nil {
		a.Logger.Error("create user", "error", err)
		writeJSON(w, 500, map[string]string{"error": "could not create account"})
		return
	}
	raw, err := a.newSession(r, user.ID, &credentialID)
	if err != nil {
		a.Logger.Error("create session", "error", err)
		writeJSON(w, 500, map[string]string{"error": "could not create session"})
		return
	}
	a.setSessionCookie(w, raw)
	a.Store.Audit(r.Context(), "registration.completed", &user.ID, &user.ID, nil, clientIP(r), r.UserAgent(), map[string]any{"admin": becameAdmin})
	writeJSON(w, http.StatusCreated, map[string]any{"redirect": safeContinuation(continuation.Continue), "administrator": becameAdmin})
}

func (a *App) loginBegin(w http.ResponseWriter, r *http.Request) {
	if !a.AuthLimiter.Allow("login:" + clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts"})
		return
	}
	var input ceremonyRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input)
	assertion, sessionData, err := a.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	txToken, err := security.RandomToken(32)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	sessionJSON, _ := json.Marshal(sessionData)
	continuationJSON, _ := json.Marshal(ceremonyContinuation{Continue: safeContinuation(input.Continue)})
	if err := a.Store.PutChallenge(r.Context(), store.Challenge{Hash: store.HashSecret(txToken), Operation: "login", TransactionID: uuid.NewString(), SessionData: sessionJSON, Continuation: continuationJSON, ExpiresAt: challengeExpiry(sessionData.Expires)}); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create challenge"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": assertion, "transaction": txToken})
}

func (a *App) loginFinish(w http.ResponseWriter, r *http.Request) {
	txToken := r.URL.Query().Get("transaction")
	challenge, err := a.Store.ConsumeChallenge(r.Context(), store.HashSecret(txToken), "login")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "challenge expired or already used"})
		return
	}
	var sessionData webauthn.SessionData
	if err = json.Unmarshal(challenge.SessionData, &sessionData); err != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid stored challenge"})
		return
	}
	userValue, credential, err := a.WebAuthn.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		user, err := a.Store.DiscoverableUser(r.Context(), rawID, userHandle)
		if err != nil {
			return nil, err
		}
		return user, nil
	}, sessionData, r)
	if err != nil {
		a.Store.Audit(r.Context(), "login.failed", nil, nil, nil, clientIP(r), r.UserAgent(), map[string]any{"reason": "webauthn_validation"})
		writeJSON(w, 400, map[string]string{"error": "passkey assertion was not valid"})
		return
	}
	user, ok := userValue.(store.WebAuthnUser)
	if !ok {
		writeJSON(w, 500, map[string]string{"error": "invalid account"})
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
	var continuation ceremonyContinuation
	_ = json.Unmarshal(challenge.Continuation, &continuation)
	a.Store.Audit(r.Context(), "login.completed", &user.ID, &user.ID, nil, clientIP(r), r.UserAgent(), nil)
	writeJSON(w, http.StatusOK, map[string]any{"redirect": safeContinuation(continuation.Continue)})
}

func (a *App) newSession(r *http.Request, userID uuid.UUID, credentialID *uuid.UUID) (string, error) {
	raw, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	session := store.Session{Hash: store.HashSecret(raw), UserID: userID, CredentialID: credentialID, AuthTime: now, CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(a.Config.SessionIdleTTL), AbsoluteExpiresAt: now.Add(a.Config.SessionAbsoluteTTL), IP: clientIP(r), UserAgent: r.UserAgent()}
	if err = a.Store.CreateSession(r.Context(), session); err != nil {
		return "", err
	}
	return raw, nil
}
