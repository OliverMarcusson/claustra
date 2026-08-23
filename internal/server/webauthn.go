package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

type ceremonyRequest struct {
	Continue  string `json:"continue"`
	Bootstrap string `json:"bootstrap"`
	CSRFScope string `json:"csrf_scope"`
}
type ceremonyContinuation struct {
	Continue      string `json:"continue"`
	BootstrapHash []byte `json:"bootstrap_hash,omitempty"`
	CSRFScope     string `json:"csrf_scope,omitempty"`
}

// resumableCSRFScope allowlists the scopes a ceremony may mint a token for.
// Reauthenticating replaces the session, which invalidates every CSRF token
// on the page that triggered it, so the form waiting to be replayed needs a
// token minted against the session that does not exist yet when that page is
// rendered. The scope travels in the challenge rather than the request body
// so a caller cannot ask for a token outside these two.
func resumableCSRFScope(value string) string {
	switch value {
	case "account", "admin-clients":
		return value
	}
	return ""
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
		a.Logger.Warn("passkey registration rejected", "error", err, "detail", webauthnFailure(err))
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
	continuationJSON, _ := json.Marshal(ceremonyContinuation{Continue: safeContinuation(input.Continue), CSRFScope: resumableCSRFScope(input.CSRFScope)})
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
	lookupFailed := false
	credentialState, credentialKnown := "", false
	userValue, credential, err := a.WebAuthn.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		user, err := a.Store.DiscoverableUser(r.Context(), rawID, userHandle)
		if err != nil {
			lookupFailed = true
			// The credential's stored state decides who owns the failure:
			// unknown means the browser holds a passkey Claustra never stored,
			// revoked means it was deliberately taken out of use, and active
			// means Claustra holds a usable credential whose asserted user
			// handle did not match the account - which would be a bug here.
			credentialState, credentialKnown = a.Store.CredentialState(r.Context(), rawID)
			a.Logger.Warn("no account for asserted passkey", "error", err,
				"credential_known", credentialKnown, "credential_state", credentialState,
				"credential_id_bytes", len(rawID), "user_handle_bytes", len(userHandle))
			return nil, err
		}
		return user, nil
	}, sessionData, r)
	if err != nil {
		reason := "webauthn_validation"
		switch {
		case lookupFailed && credentialState == "revoked":
			reason = "revoked_credential"
		case lookupFailed:
			reason = "unknown_credential"
		}
		// The error is the only thing that says which of a dozen checks
		// rejected the assertion. Discarding it left the failure undebuggable
		// from the outside; it names protocol state, never key material.
		a.Logger.Warn("passkey assertion rejected", "reason", reason, "error", err, "detail", webauthnFailure(err))
		a.Store.Audit(r.Context(), "login.failed", nil, nil, nil, clientIP(r), r.UserAgent(), map[string]any{"reason": reason})
		writeJSON(w, 400, map[string]string{"error": assertionFailureMessage(lookupFailed, credentialState, credentialKnown)})
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
	response := map[string]any{"redirect": safeContinuation(continuation.Continue)}
	if continuation.CSRFScope != "" {
		response["csrf"] = security.CSRF(raw, continuation.CSRFScope)
	}
	writeJSON(w, http.StatusOK, response)
}

// assertionFailureMessage says which passkey problem this is. A passkey the
// account no longer has is not a failed assertion, and saying so sends people
// hunting for a broken key instead of picking the one that works. Revoking a
// passkey does not remove it from the authenticator, so it keeps being
// offered; a registration that fails after the browser has already created the
// credential leaves the same kind of leftover behind, one Claustra has never
// seen at all. Anything else really is a rejected assertion.
func assertionFailureMessage(lookupFailed bool, credentialState string, credentialKnown bool) string {
	switch {
	case lookupFailed && credentialState == "revoked":
		return "that passkey was revoked - use a different one"
	case lookupFailed && !credentialKnown:
		return "that passkey is not registered here - pick another, or create an account"
	}
	return "passkey assertion was not valid"
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

// webauthnFailure unwraps the library's error into the part that identifies
// which check failed. Details and DevInfo describe protocol state - flags,
// origins, counters - and never carry key material or the assertion itself.
func webauthnFailure(err error) string {
	var protocolError *protocol.Error
	if errors.As(err, &protocolError) {
		return strings.TrimSpace(protocolError.Type + ": " + protocolError.Details + " " + protocolError.DevInfo)
	}
	return err.Error()
}
