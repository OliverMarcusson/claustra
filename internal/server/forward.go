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
			subject, _ := a.Store.ForwardSubject(r.Context(), session.UserID, host)
			w.Header().Set("X-Claustra-User", subject)
			w.Header().Set("X-Claustra-Sub", subject)
			w.WriteHeader(200)
			return
		}
	}
	method := r.Header.Get("X-Forwarded-Method")
	if method == "" {
		method = "GET"
	}
	uri := safeReturnPath(r.Header.Get("X-Forwarded-Uri"))
	accept := r.Header.Get("Accept")
	if (method == "GET" || method == "HEAD") && strings.Contains(accept, "text/html") {
		target := a.Config.Issuer + "/forward-auth/authorize?host=" + url.QueryEscape(host) + "&rd=" + url.QueryEscape(uri)
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="claustra"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
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
