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

// adminClientsPage builds the admin page's template data. Three handlers
// re-render this page after acting, and when the shape was spelled out at each
// of them it was one edit away from the views disagreeing about what the page
// shows.
func (a *App) adminClientsPage(r *http.Request, session sessionContext, extra map[string]any) map[string]any {
	clients, _ := a.Store.ListClients(r.Context())
	hosts, _ := a.Store.ListForwardHosts(r.Context())
	admins, _ := a.Store.ListAdmins(r.Context())
	data := map[string]any{
		"Title": "Clients", "SignedIn": true, "Admin": true, "NavAdmin": true,
		"LogoutCSRF":   security.CSRF(session.RawToken, "account"),
		"Issuer":       a.Config.Issuer,
		"Clients":      clients,
		"ForwardHosts": hosts,
		"Admins":       admins,
		"CSRF":         security.CSRF(session.RawToken, "admin-clients"),
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// parseEmailList reads the newline- or comma-separated addresses an admin typed
// into an allowlist field and returns them in the normalized form the lookup
// joins on. One bad address fails the whole list rather than being dropped
// quietly: a silently discarded entry reads as "access granted" until someone
// is locked out.
func parseEmailList(value string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	split := func(r rune) bool { return strings.ContainsRune("\r\n, \t;", r) }
	for _, field := range strings.FieldsFunc(value, split) {
		normalized, err := normalizeEmail(field)
		if err != nil {
			return nil, err
		}
		if !seen[normalized] {
			seen[normalized] = true
			out = append(out, normalized)
		}
	}
	return out, nil
}
func (a *App) adminClients(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if !a.requireRecent(w, r, session) {
		return
	}
	if _, err := a.Store.ListClients(r.Context()); err != nil {
		http.Error(w, "could not list clients", 500)
		return
	}
	a.render(w, 200, "admin_clients", a.adminClientsPage(r, session, nil))
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
	policy := r.Form.Get("access_policy")
	if policy == "" {
		policy = store.AccessAllowlist
	}
	if !store.ValidAccessPolicy(policy) {
		http.Error(w, "invalid access policy", 400)
		return
	}
	emails, err := parseEmailList(r.Form.Get("allowed_emails"))
	if err != nil {
		http.Error(w, "invalid email address in allowlist", 400)
		return
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
	client := store.NewClient{Client: store.Client{ID: id, Name: name, LogoURI: logo, HomepageURI: homepage, PrivacyPolicyURI: privacy, Trusted: trusted, AccessPolicy: policy, RedirectURIs: []string{redirect}, AllowedScopes: scopes, PreapprovedScopes: preapproved}, SecretHash: store.HashSecret(secret), CreatedBy: session.User.ID}
	if _, err = a.Store.CreateClient(r.Context(), client); err != nil {
		http.Error(w, "could not create client", 409)
		return
	}
	for _, email := range emails {
		if err = a.Store.AllowClientEmail(r.Context(), id, email, session.User.ID); err != nil {
			http.Error(w, "could not store allowlist", 500)
			return
		}
	}
	a.Store.Audit(r.Context(), "client.created", &session.User.ID, nil, &id, clientIP(r), r.UserAgent(), map[string]any{"trusted": trusted, "scopes": scopes, "access_policy": policy, "allowed_emails": len(emails)})
	a.render(w, 201, "admin_clients", a.adminClientsPage(r, session, map[string]any{"NewSecret": secret}))
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
	a.Store.Audit(r.Context(), "client.secret_rotated", &session.User.ID, nil, &clientID, clientIP(r), r.UserAgent(), nil)
	a.render(w, 201, "admin_clients", a.adminClientsPage(r, session, map[string]any{"NewSecret": secret}))
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
	policy := r.Form.Get("access_policy")
	if policy == "" {
		policy = store.AccessAllowlist
	}
	if !store.ValidAccessPolicy(policy) {
		http.Error(w, "invalid access policy", 400)
		return
	}
	emails, err := parseEmailList(r.Form.Get("allowed_emails"))
	if err != nil {
		http.Error(w, "invalid email address in allowlist", 400)
		return
	}
	if err := a.Store.CreateForwardHost(r.Context(), host, name, policy, session.User.ID); err != nil {
		http.Error(w, "could not create host", 409)
		return
	}
	for _, email := range emails {
		if err := a.Store.AllowForwardEmail(r.Context(), host, email, session.User.ID); err != nil {
			http.Error(w, "could not store allowlist", 500)
			return
		}
	}
	a.Store.Audit(r.Context(), "forward_host.created", &session.User.ID, nil, nil, clientIP(r), r.UserAgent(), map[string]any{"host": host, "access_policy": policy, "allowed_emails": len(emails)})
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

// adminClientAccess manages one client's access policy and allowlist.
//
// The three verbs share a route because they share every precondition — admin,
// recent authentication, CSRF, a client that exists — and splitting them into
// three endpoints made it possible to add a fourth that forgot one of them.
func (a *App) adminClientAccess(w http.ResponseWriter, r *http.Request) {
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
	switch r.Form.Get("action") {
	case "policy":
		policy := r.Form.Get("policy")
		if err := a.Store.SetClientAccessPolicy(r.Context(), clientID, policy); err != nil {
			http.Error(w, "could not update policy", 400)
			return
		}
		a.Store.Audit(r.Context(), "client.access_policy_changed", &session.User.ID, nil, &clientID, clientIP(r), r.UserAgent(), map[string]any{"policy": policy})
	case "allow":
		email, err := normalizeEmail(r.Form.Get("email"))
		if err != nil {
			http.Error(w, "invalid email address", 400)
			return
		}
		if err = a.Store.AllowClientEmail(r.Context(), clientID, email, session.User.ID); err != nil {
			http.Error(w, "could not add address", 400)
			return
		}
		a.Store.Audit(r.Context(), "client.access_granted", &session.User.ID, nil, &clientID, clientIP(r), r.UserAgent(), map[string]any{"email": email})
	case "deny":
		email, err := normalizeEmail(r.Form.Get("email"))
		if err != nil {
			http.Error(w, "invalid email address", 400)
			return
		}
		if err = a.Store.DenyClientEmail(r.Context(), clientID, email); err != nil {
			http.Error(w, "could not remove address", 400)
			return
		}
		a.Store.Audit(r.Context(), "client.access_revoked", &session.User.ID, nil, &clientID, clientIP(r), r.UserAgent(), map[string]any{"email": email})
	default:
		http.Error(w, "unknown action", 400)
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

// adminForwardAccess is the same three verbs for a forward-auth host.
func (a *App) adminForwardAccess(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireAdmin(w, r)
	if !ok || !a.requireRecent(w, r, session) {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "admin-clients", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	host := strings.ToLower(strings.TrimSpace(r.Form.Get("host")))
	switch r.Form.Get("action") {
	case "policy":
		policy := r.Form.Get("policy")
		if err := a.Store.SetForwardAccessPolicy(r.Context(), host, policy); err != nil {
			http.Error(w, "could not update policy", 400)
			return
		}
		a.Store.Audit(r.Context(), "forward_host.access_policy_changed", &session.User.ID, nil, nil, clientIP(r), r.UserAgent(), map[string]any{"host": host, "policy": policy})
	case "allow":
		email, err := normalizeEmail(r.Form.Get("email"))
		if err != nil {
			http.Error(w, "invalid email address", 400)
			return
		}
		if err = a.Store.AllowForwardEmail(r.Context(), host, email, session.User.ID); err != nil {
			http.Error(w, "could not add address", 400)
			return
		}
		a.Store.Audit(r.Context(), "forward_host.access_granted", &session.User.ID, nil, nil, clientIP(r), r.UserAgent(), map[string]any{"host": host, "email": email})
	case "deny":
		email, err := normalizeEmail(r.Form.Get("email"))
		if err != nil {
			http.Error(w, "invalid email address", 400)
			return
		}
		if err = a.Store.DenyForwardEmail(r.Context(), host, email); err != nil {
			http.Error(w, "could not remove address", 400)
			return
		}
		a.Store.Audit(r.Context(), "forward_host.access_revoked", &session.User.ID, nil, nil, clientIP(r), r.UserAgent(), map[string]any{"host": host, "email": email})
	default:
		http.Error(w, "unknown action", 400)
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}
