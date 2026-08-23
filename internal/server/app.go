package server

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/olivermarcusson/claustra/internal/config"
	claustramail "github.com/olivermarcusson/claustra/internal/mail"
	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

const sessionCookie = "__Host-claustra"

type App struct {
	Config              config.Config
	Store               *store.Store
	WebAuthn            *webauthn.WebAuthn
	SigningKey          *rsa.PrivateKey
	SigningKeyID        string
	PreviousSigningKeys []PublicSigningKey
	Logger              *slog.Logger
	Templates           *template.Template
	AuthLimiter         *security.Limiter
	EmailLimiter        *security.Limiter
	Mailer              claustramail.Sender
	IssuerHost          string
}

type PublicSigningKey struct {
	Key   *rsa.PublicKey
	KeyID string
}

// ChallengeTTL bounds a WebAuthn ceremony. It is also the lifetime written to
// webauthn_challenges, so the row and the library agree on when a ceremony is
// too old to finish.
const ChallengeTTL = 5 * time.Minute

// newWebAuthn builds the relying party. Timeouts.Enforce is the load-bearing
// setting: without it the library leaves SessionData.Expires at the zero time,
// every challenge row is stored as expired, and every ceremony fails to finish
// with "challenge expired or already used". The durations are stated rather
// than inherited so a library default cannot quietly change the window.
func newWebAuthn(cfg config.Config) (*webauthn.WebAuthn, error) {
	timeouts := webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL}
	return webauthn.New(&webauthn.Config{
		RPID: cfg.RPID, RPDisplayName: cfg.RPDisplayName, RPOrigins: []string{cfg.Issuer},
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired},
		Timeouts:               webauthn.TimeoutsConfig{Login: timeouts, Registration: timeouts},
	})
}

// challengeExpiry is what goes in the database. The library fills Expires in
// only while it is enforcing timeouts; a zero there would store a challenge
// that ConsumeChallenge can never match, so it falls back rather than trusting
// the configuration to stay correct.
func challengeExpiry(expires time.Time) time.Time {
	if expires.IsZero() {
		return time.Now().UTC().Add(ChallengeTTL)
	}
	return expires.UTC()
}

func New(cfg config.Config, st *store.Store, signingKey *rsa.PrivateKey, keyID string, previous []PublicSigningKey, logger *slog.Logger) (*App, error) {
	wa, err := newWebAuthn(cfg)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("root").Funcs(templateFuncs).Parse(pageTemplates)
	if err != nil {
		return nil, err
	}
	issuerURL, _ := url.Parse(cfg.Issuer)
	return &App{Config: cfg, Store: st, WebAuthn: wa, SigningKey: signingKey, SigningKeyID: keyID, PreviousSigningKeys: previous, Logger: logger, Templates: tmpl, AuthLimiter: security.NewLimiter(30, time.Minute), EmailLimiter: security.NewLimiter(5, time.Hour), Mailer: claustramail.SMTP{Config: cfg.SMTP}, IssuerHost: strings.ToLower(issuerURL.Hostname())}, nil
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.home)
	mux.HandleFunc("GET /static/passkey.js", a.passkeyAsset)
	mux.HandleFunc("GET /static/claustra.css", a.styleAsset)
	mux.HandleFunc("GET /static/claustra-button.css", a.buttonKitAsset)
	mux.HandleFunc("GET /static/mark.svg", a.markAsset)
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /.well-known/openid-configuration", a.discovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.oauthMetadata)
	mux.HandleFunc("GET /jwks.json", a.jwks)
	mux.HandleFunc("GET /register", a.registerPage)
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /webauthn/register/begin", a.registrationBegin)
	mux.HandleFunc("POST /webauthn/register/finish", a.registrationFinish)
	mux.HandleFunc("POST /webauthn/login/begin", a.loginBegin)
	mux.HandleFunc("POST /webauthn/login/finish", a.loginFinish)
	mux.HandleFunc("GET /authorize", a.authorize)
	mux.HandleFunc("POST /authorize/consent", a.authorizeConsent)
	mux.HandleFunc("POST /token", a.token)
	mux.HandleFunc("GET /userinfo", a.userinfo)
	mux.HandleFunc("GET /avatar", a.avatar)
	mux.HandleFunc("POST /revoke", a.revoke)
	mux.HandleFunc("GET /account", a.account)
	mux.HandleFunc("GET /account/avatar", a.accountAvatar)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("POST /logout/all", a.logoutAll)
	mux.HandleFunc("POST /profile", a.profileUpdate)
	mux.HandleFunc("POST /profile/avatar", a.avatarUpload)
	mux.HandleFunc("GET /account/passkeys/add", a.addPasskeyPage)
	mux.HandleFunc("POST /webauthn/passkey/begin", a.addPasskeyBegin)
	mux.HandleFunc("POST /webauthn/passkey/finish", a.addPasskeyFinish)
	mux.HandleFunc("POST /account/passkeys/revoke", a.revokePasskey)
	mux.HandleFunc("POST /account/sessions/revoke", a.revokeAccountSession)
	mux.HandleFunc("POST /account/consents/revoke", a.revokeConsent)
	mux.HandleFunc("GET /email/verify", a.emailVerify)
	mux.HandleFunc("GET /recover", a.recoveryPage)
	mux.HandleFunc("POST /recover", a.recoveryRequest)
	mux.HandleFunc("GET /recover/complete", a.recoveryCompletePage)
	mux.HandleFunc("POST /recover/complete", a.recoveryComplete)
	mux.HandleFunc("POST /webauthn/recovery/begin", a.recoveryBegin)
	mux.HandleFunc("POST /webauthn/recovery/finish", a.recoveryFinish)
	mux.HandleFunc("POST /recovery/cancel", a.recoveryCancel)
	mux.HandleFunc("POST /account/delete", a.deleteAccount)
	mux.HandleFunc("GET /delete/cancel", a.deletionCancelPage)
	mux.HandleFunc("GET /delete/cancel/email", a.deletionCancelEmail)
	mux.HandleFunc("POST /webauthn/delete-cancel/begin", a.deletionCancelBegin)
	mux.HandleFunc("POST /webauthn/delete-cancel/finish", a.deletionCancelFinish)
	mux.HandleFunc("GET /admin/clients", a.adminClients)
	mux.HandleFunc("POST /admin/clients", a.adminCreateClient)
	mux.HandleFunc("POST /admin/clients/rotate", a.adminRotateClient)
	mux.HandleFunc("POST /admin/clients/toggle", a.adminToggleClient)
	mux.HandleFunc("POST /admin/forward-hosts", a.adminCreateForwardHost)
	mux.HandleFunc("POST /admin/roles", a.adminSetRole)
	mux.HandleFunc("GET /forward-auth/verify", a.forwardVerify)
	mux.HandleFunc("GET /forward-auth/authorize", a.forwardAuthorize)
	mux.HandleFunc("GET /_claustra/callback", a.forwardCallback)
	mux.HandleFunc("POST /_claustra/logout", a.forwardLogout)
	return a.originBoundary(a.securityHeaders(a.recoverer(mux)))
}

func (a *App) originBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		host := requestHost(r)
		servicePath := path == "/forward-auth/verify" || strings.HasPrefix(path, "/_claustra/")
		if !servicePath && path != "/healthz" && host != a.IssuerHost {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if a.Config.SecureCookies {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				a.Logger.Error("panic", "value", value)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type sessionContext struct {
	Session  store.Session
	User     store.WebAuthnUser
	RawToken string
	Admin    bool
}
type ctxKey int

const sessionKey ctxKey = 1

func (a *App) currentSession(r *http.Request) (sessionContext, error) {
	cookie, err := r.Cookie(a.sessionCookieName())
	if err != nil {
		return sessionContext{}, store.ErrNotFound
	}
	session, err := a.Store.SessionByToken(r.Context(), cookie.Value, a.Config.SessionIdleTTL)
	if err != nil {
		return sessionContext{}, err
	}
	user, err := a.Store.UserByID(r.Context(), session.UserID)
	if err != nil {
		return sessionContext{}, err
	}
	return sessionContext{Session: session, User: user, RawToken: cookie.Value, Admin: a.Store.IsAdmin(r.Context(), user.ID)}, nil
}

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) (sessionContext, bool) {
	s, err := a.currentSession(r)
	if err != nil {
		next := "/login?continue=" + urlQueryEscape(relativeRequestURI(r))
		http.Redirect(w, r, next, http.StatusSeeOther)
		return sessionContext{}, false
	}
	return s, true
}
func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) (sessionContext, bool) {
	s, ok := a.requireSession(w, r)
	if !ok {
		return sessionContext{}, false
	}
	if !s.Admin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionContext{}, false
	}
	return s, true
}

func (a *App) setSessionCookie(w http.ResponseWriter, raw string) {
	http.SetCookie(w, &http.Cookie{Name: a.sessionCookieName(), Value: raw, Path: "/", Secure: a.Config.SecureCookies, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(a.Config.SessionAbsoluteTTL.Seconds())})
}
func (a *App) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: a.sessionCookieName(), Value: "", Path: "/", Secure: a.Config.SecureCookies, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (a *App) sessionCookieName() string {
	if a.Config.SecureCookies {
		return sessionCookie
	}
	return "claustra-dev"
}

func (a *App) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.Templates.ExecuteTemplate(w, name, data); err != nil {
		a.Logger.Error("render template", "template", name, "error", err)
	}
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func oauthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.Store.Pool.Ping(ctx); err != nil {
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	s, err := a.currentSession(r)
	data := map[string]any{"SignedIn": err == nil, "User": s.User, "Admin": s.Admin}
	if err == nil {
		data["LogoutCSRF"] = security.CSRF(s.RawToken, "account")
	}
	a.render(w, http.StatusOK, "home", data)
}

func relativeRequestURI(r *http.Request) string {
	value := r.URL.RequestURI()
	if !strings.HasPrefix(value, "/") {
		return "/"
	}
	return value
}
func safeContinuation(value string) string {
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		return value
	}
	return "/account"
}
func urlQueryEscape(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(value, "%", "%25"), "&", "%26"), "?", "%3F")
}
func formScopes(scopes []string) string { return strings.Join(scopes, " ") }
func hasScope(scopes []string, want string) bool {
	for _, v := range scopes {
		if v == want {
			return true
		}
	}
	return false
}
func clientIP(r *http.Request) string { return security.ClientIP(r) }

var _ = errors.Is
var _ = fmt.Sprintf
