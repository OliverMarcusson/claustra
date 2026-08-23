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
