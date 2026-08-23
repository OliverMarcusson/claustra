package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

const forwardCookie = "__Host-claustra-rp"

func requestHost(r *http.Request) string {
	host := strings.ToLower(r.Host)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return parsed
	}
	return strings.TrimSuffix(host, ".")
}
func safeReturnPath(value string) string {
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		return value
	}
	return "/"
}

func (a *App) forwardVerify(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r)
	registered, err := a.Store.ForwardHost(r.Context(), host)
	if err != nil || !registered.Enabled {
		http.Error(w, "unknown relying party", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(a.forwardCookieName()); err == nil {
		session, err := a.Store.ForwardSessionByRaw(r.Context(), cookie.Value, host)
		if err == nil {
			// The allowlist is consulted per request, not once when the
			// cookie was minted. Removing an address has to take effect
			// now, not whenever the forward session happens to expire.
			allowed, err := a.Store.ForwardAccessAllowed(r.Context(), host, session.UserID)
			if err != nil {
				http.Error(w, "could not verify access", http.StatusInternalServerError)
				return
			}
			if allowed {
				subject, _ := a.Store.ForwardSubject(r.Context(), session.UserID, host)
				w.Header().Set("X-Claustra-User", subject)
				w.Header().Set("X-Claustra-Sub", subject)
				w.WriteHeader(200)
				return
			}
			// Signed in and rejected is not the same as not signed in.
			// Send browsers to the authorize endpoint, which renders the
			// denial page on Claustra's own origin; anything else gets a
			// plain 403 rather than a sign-in prompt it cannot satisfy.
			if isBrowserNavigation(r) {
				a.redirectToForwardAuthorize(w, host, r)
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	if isBrowserNavigation(r) {
		a.redirectToForwardAuthorize(w, host, r)
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="claustra"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// isBrowserNavigation reports whether this is a top-level HTML navigation, the
// only kind of request that can usefully be sent somewhere to be resolved. API,
// XHR and non-idempotent requests get a status code instead.
func isBrowserNavigation(r *http.Request) bool {
	method := r.Header.Get("X-Forwarded-Method")
	if method == "" {
		method = "GET"
	}
	return (method == "GET" || method == "HEAD") && strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (a *App) redirectToForwardAuthorize(w http.ResponseWriter, host string, r *http.Request) {
	uri := safeReturnPath(r.Header.Get("X-Forwarded-Uri"))
	target := a.Config.Issuer + "/forward-auth/authorize?host=" + url.QueryEscape(host) + "&rd=" + url.QueryEscape(uri)
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

func (a *App) forwardAuthorize(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.URL.Query().Get("host"))
	rd := safeReturnPath(r.URL.Query().Get("rd"))
	registered, err := a.Store.ForwardHost(r.Context(), host)
	if err != nil || !registered.Enabled {
		http.Error(w, "unknown relying party", 403)
		return
	}
	session, err := a.currentSession(r)
	if err != nil {
		http.Redirect(w, r, "/login?continue="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	allowed, err := a.Store.ForwardAccessAllowed(r.Context(), host, session.User.ID)
	if err != nil {
		http.Error(w, "could not authorize", 500)
		return
	}
	if !allowed {
		a.denyService(w, r, session, registered.Name)
		return
	}
	raw, err := security.RandomToken(32)
	if err != nil {
		http.Error(w, "could not authorize", 500)
		return
	}
	ticket := store.ForwardTicket{Hash: store.HashSecret(raw), SSOSessionHash: session.Session.Hash, UserID: session.User.ID, Host: host, ReturnPath: rd, ExpiresAt: time.Now().Add(30 * time.Second)}
	if err = a.Store.PutForwardTicket(r.Context(), ticket); err != nil {
		http.Error(w, "could not authorize", 500)
		return
	}
	a.Store.Audit(r.Context(), "forward.ticket_issued", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), map[string]any{"host": host})
	http.Redirect(w, r, "https://"+host+"/_claustra/callback?ticket="+url.QueryEscape(raw), http.StatusFound)
}

func (a *App) forwardCallback(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r)
	ticket, err := a.Store.ConsumeForwardTicket(r.Context(), store.HashSecret(r.URL.Query().Get("ticket")), host)
	if err != nil {
		http.Error(w, "invalid or expired ticket", 400)
		return
	}
	raw, err := security.RandomToken(32)
	if err != nil {
		http.Error(w, "could not create session", 500)
		return
	}
	expires := time.Now().Add(a.Config.SessionIdleTTL)
	if err = a.Store.PutForwardSession(r.Context(), store.ForwardSession{Hash: store.HashSecret(raw), SSOSessionHash: ticket.SSOSessionHash, UserID: ticket.UserID, Host: host, ExpiresAt: expires}); err != nil {
		http.Error(w, "could not create session", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: a.forwardCookieName(), Value: raw, Path: "/", Secure: a.Config.SecureCookies, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(a.Config.SessionIdleTTL.Seconds())})
	http.Redirect(w, r, ticket.ReturnPath, http.StatusSeeOther)
}

func (a *App) forwardLogout(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r)
	origin := r.Header.Get("Origin")
	if origin != "https://"+host {
		http.Error(w, "invalid origin", 403)
		return
	}
	cookie, err := r.Cookie(a.forwardCookieName())
	if err == nil {
		_ = a.Store.RevokeForwardSession(r.Context(), store.HashSecret(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: a.forwardCookieName(), Value: "", Path: "/", Secure: a.Config.SecureCookies, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) forwardCookieName() string {
	if a.Config.SecureCookies {
		return forwardCookie
	}
	return "claustra-rp-dev"
}
