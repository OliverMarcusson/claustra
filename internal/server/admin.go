package server

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

var clientIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

func (a *App) adminClients(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.requireRecent(w, r, session) {
		return
	}
	clients, err := a.Store.ListClients(r.Context())
	if err != nil {
		http.Error(w, "could not list clients", 500)
		return
	}
	hosts, _ := a.Store.ListForwardHosts(r.Context())
	admins, _ := a.Store.ListAdmins(r.Context())
	a.render(w, 200, "admin_clients", map[string]any{"Title": "Clients", "SignedIn": true, "Admin": true, "NavAdmin": true, "Issuer": a.Config.Issuer, "Clients": clients, "ForwardHosts": hosts, "Admins": admins, "CSRF": security.CSRF(session.RawToken, "admin-clients")})
}

func (a *App) adminCreateClient(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.requireRecent(w, r, session) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "admin-clients", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	id := strings.TrimSpace(r.Form.Get("id"))
	name := strings.TrimSpace(r.Form.Get("name"))
	redirect := strings.TrimSpace(r.Form.Get("redirect_uri"))
	if !clientIDPattern.MatchString(id) || name == "" || len([]rune(name)) > 100 || !store.ValidHTTPSURL(redirect) {
		http.Error(w, "invalid client metadata", 400)
		return
	}
	scopes, err := store.NormalizeScopes(r.Form.Get("scopes"))
	if err != nil {
		http.Error(w, "invalid scopes", 400)
		return
	}
	logo, homepage, privacy := strings.TrimSpace(r.Form.Get("logo_uri")), strings.TrimSpace(r.Form.Get("homepage_uri")), strings.TrimSpace(r.Form.Get("privacy_policy_uri"))
	for _, value := range []string{logo, homepage, privacy} {
		if value != "" && !store.ValidHTTPSURL(value) {
			http.Error(w, "metadata URLs must use HTTPS", 400)
			return
		}
	}
	trusted := r.Form.Get("trusted") == "yes"
	preapproved := []string{"openid"}
	if trusted && r.Form.Get("preapprove_profile") == "yes" && hasScope(scopes, "profile") {
		preapproved = append(preapproved, "profile")
	}
	if trusted && r.Form.Get("preapprove_email") == "yes" && hasScope(scopes, "email") {
		preapproved = append(preapproved, "email")
	}
	secret, err := security.RandomToken(32)
	if err != nil {
		http.Error(w, "could not create secret", 500)
		return
	}
	client := store.NewClient{Client: store.Client{ID: id, Name: name, LogoURI: logo, HomepageURI: homepage, PrivacyPolicyURI: privacy, Trusted: trusted, RedirectURIs: []string{redirect}, AllowedScopes: scopes, PreapprovedScopes: preapproved}, SecretHash: store.HashSecret(secret), CreatedBy: session.User.ID}
	if _, err = a.Store.CreateClient(r.Context(), client); err != nil {
		http.Error(w, "could not create client", 409)
		return
	}
	clients, _ := a.Store.ListClients(r.Context())
	hosts, _ := a.Store.ListForwardHosts(r.Context())
	admins, _ := a.Store.ListAdmins(r.Context())
	a.Store.Audit(r.Context(), "client.created", &session.User.ID, nil, &id, clientIP(r), r.UserAgent(), map[string]any{"trusted": trusted, "scopes": scopes})
	a.render(w, 201, "admin_clients", map[string]any{"Title": "Clients", "SignedIn": true, "Admin": true, "NavAdmin": true, "Issuer": a.Config.Issuer, "Clients": clients, "ForwardHosts": hosts, "Admins": admins, "CSRF": security.CSRF(session.RawToken, "admin-clients"), "NewSecret": secret})
}

func (a *App) adminRotateClient(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok || !a.requireRecent(w, r, session) {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "admin-clients", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	clientID := r.Form.Get("client_id")
	secret, _ := security.RandomToken(32)
	if _, err := a.Store.RotateClientSecret(r.Context(), clientID, store.HashSecret(secret)); err != nil {
		http.Error(w, "could not rotate secret", 400)
		return
	}
	clients, _ := a.Store.ListClients(r.Context())
	hosts, _ := a.Store.ListForwardHosts(r.Context())
	admins, _ := a.Store.ListAdmins(r.Context())
	a.Store.Audit(r.Context(), "client.secret_rotated", &session.User.ID, nil, &clientID, clientIP(r), r.UserAgent(), nil)
	a.render(w, 201, "admin_clients", map[string]any{"Title": "Clients", "SignedIn": true, "Admin": true, "NavAdmin": true, "Issuer": a.Config.Issuer, "Clients": clients, "ForwardHosts": hosts, "Admins": admins, "CSRF": security.CSRF(session.RawToken, "admin-clients"), "NewSecret": secret})
}

func (a *App) adminToggleClient(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok || !a.requireRecent(w, r, session) {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "admin-clients", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	clientID := r.Form.Get("client_id")
	enabled := r.Form.Get("enabled") == "true"
	if err := a.Store.SetClientEnabled(r.Context(), clientID, enabled); err != nil {
		http.Error(w, "could not update client", 400)
		return
	}
	a.Store.Audit(r.Context(), "client.status_changed", &session.User.ID, nil, &clientID, clientIP(r), r.UserAgent(), map[string]any{"enabled": enabled})
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

func (a *App) adminCreateForwardHost(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok || !a.requireRecent(w, r, session) {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "admin-clients", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Form.Get("host")), "."))
	name := strings.TrimSpace(r.Form.Get("name"))
	if net.ParseIP(host) != nil || strings.Contains(host, ":") || !strings.Contains(host, ".") || name == "" {
		http.Error(w, "invalid host", 400)
		return
	}
	if err := a.Store.CreateForwardHost(r.Context(), host, name, session.User.ID); err != nil {
		http.Error(w, "could not create host", 409)
		return
	}
	a.Store.Audit(r.Context(), "forward_host.created", &session.User.ID, nil, nil, clientIP(r), r.UserAgent(), map[string]any{"host": host})
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

func (a *App) adminSetRole(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok || !a.requireRecent(w, r, session) {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "admin-clients", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	target, err := uuid.Parse(r.Form.Get("user_id"))
	if err != nil {
		http.Error(w, "invalid user", 400)
		return
	}
	enabled := r.Form.Get("admin") == "true"
	if err = a.Store.SetAdmin(r.Context(), session.User.ID, target, enabled); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.Store.Audit(r.Context(), "role.admin_changed", &session.User.ID, &target, nil, clientIP(r), r.UserAgent(), map[string]any{"enabled": enabled})
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}
