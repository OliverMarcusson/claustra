package server

import (
	"net/http"

	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

// denyService renders the page a signed-in user reaches when a service admits
// only listed addresses and theirs is not among them.
//
// This is deliberately a terminal page rather than a bounce back to the
// relying party. The account is valid and the sign-in worked; sending the
// browser back to a service that will only redirect it here again produces a
// loop, and an OAuth error code on the client's own error page tells the person
// nothing about why. The page names the address that was checked, because the
// usual cause is being signed in as the wrong account or holding an address
// that was never verified.
func (a *App) denyService(w http.ResponseWriter, r *http.Request, session sessionContext, service string) {
	email := ""
	if session.User.Email != nil && session.User.EmailVerified {
		email = *session.User.Email
	}
	a.Store.Audit(r.Context(), "access.denied", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), map[string]any{"service": service})
	a.render(w, http.StatusForbidden, "denied", map[string]any{
		"Title":      "No access",
		"SignedIn":   true,
		"Admin":      session.Admin,
		"LogoutCSRF": security.CSRF(session.RawToken, "account"),
		"Service":    service,
		"Email":      email,
	})
}

// permitClient reports whether this session may complete an authorization
// request for the client, rendering the denial page itself when it may not.
func (a *App) permitClient(w http.ResponseWriter, r *http.Request, session sessionContext, client store.Client) bool {
	allowed, err := a.Store.ClientAccessAllowed(r.Context(), client.ID, session.User.ID)
	if err != nil {
		http.Error(w, "authorization failed", http.StatusInternalServerError)
		return false
	}
	if !allowed {
		a.denyService(w, r, session, client.Name)
		return false
	}
	return true
}

// stepUp runs the passkey ceremony again for an authorization request that
// asked for fresh authentication, then returns the browser to that same
// request.
//
// The continuation drops prompt, and drops max_age when it is zero. Either
// would demand the ceremony again the moment it succeeded, which is a loop with
// no exit. A non-zero max_age is safe to keep: the ceremony mints a session
// whose auth_time is now, so the check passes on the way back.
//
// Freshness is not enforced by this bounce alone. The ID token reports the
// session's real auth_time, and a relying party that cares — one confirming a
// destructive action rather than just logging someone in — is expected to
// check that claim rather than trust that the prompt was honoured.
func (a *App) stepUp(w http.ResponseWriter, r *http.Request, session sessionContext, q authorizationRequest) {
	target := *r.URL
	values := target.Query()
	values.Del("prompt")
	if q.oneShotMaxAge() {
		// max_age=0 can never be satisfied by an existing session, so leaving
		// it in place would demand the ceremony again on the way back.
		values.Del("max_age")
	}
	target.RawQuery = values.Encode()

	a.Store.Audit(r.Context(), "authorization.step_up", &session.User.ID, &session.User.ID, &q.ClientID, clientIP(r), r.UserAgent(), map[string]any{"prompt": q.Prompt, "max_age": q.MaxAge})
	a.render(w, http.StatusOK, "reauth", map[string]any{
		"Title": "Confirm it is you", "SignedIn": true, "Admin": session.Admin,
		"LogoutCSRF": security.CSRF(session.RawToken, "account"),
		"Continue":   safeContinuation(target.RequestURI()),
	})
}
