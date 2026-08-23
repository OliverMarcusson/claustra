package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/store"
)

func (a *App) account(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	recoveryID, recoveryDue, pending := a.Store.PendingRecovery(r.Context(), session.User.ID)
	sessions, _ := a.Store.ListSessions(r.Context(), session.User.ID)
	sessionViews := make([]map[string]any, 0, len(sessions))
	for _, v := range sessions {
		sessionViews = append(sessionViews, map[string]any{"Hash": base64.RawURLEncoding.EncodeToString(v.Hash), "Current": string(v.Hash) == string(session.Session.Hash), "LastSeen": v.LastSeenAt, "IP": v.IP, "UserAgent": v.UserAgent})
	}
	consents, _ := a.Store.ListConsents(r.Context(), session.User.ID)
	a.render(w, 200, "account", map[string]any{"Title": "Account", "SignedIn": true, "NavAccount": true, "LogoutCSRF": security.CSRF(session.RawToken, "account"), "HasAvatar": a.Store.HasAvatar(r.Context(), session.User.ID), "User": session.User, "Admin": session.Admin, "CSRF": security.CSRF(session.RawToken, "account"), "PendingRecovery": pending, "RecoveryID": recoveryID, "RecoveryDue": recoveryDue, "Sessions": sessionViews, "Consents": consents})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "account", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	if err := a.Store.RevokeSession(r.Context(), session.Session.Hash); err != nil {
		http.Error(w, "could not sign out", 500)
		return
	}
	a.clearSessionCookie(w)
	a.Store.Audit(r.Context(), "session.revoked", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) logoutAll(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "account", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	if err := a.Store.RevokeAllSessions(r.Context(), session.User.ID); err != nil {
		http.Error(w, "could not sign out", 500)
		return
	}
	a.clearSessionCookie(w)
	a.Store.Audit(r.Context(), "sessions.revoked_all", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ReauthWindow is how recently a passkey must have been used before Claustra
// will change passkeys, emails, roles, clients or the account itself.
const ReauthWindow = 5 * time.Minute

func (a *App) requireRecent(w http.ResponseWriter, r *http.Request, session sessionContext) bool {
	if time.Since(session.Session.AuthTime) <= ReauthWindow {
		return true
	}
	// Signing in again is the whole remedy, so the page says so and links
	// straight at it. Telling someone to sign out and back in was both a
	// dead end - the response carried no navigation at all - and wrong: the
	// ceremony alone refreshes auth_time, no sign-out required.
	a.render(w, http.StatusForbidden, "reauth", map[string]any{
		"Title": "Confirm it is you", "SignedIn": true, "Admin": session.Admin,
		"LogoutCSRF": security.CSRF(session.RawToken, "account"),
		"Continue":   reauthTarget(r),
		"Resume":     pendingSubmission(w, r),
	})
	return false
}

// resumeField is one value of the form that requireRecent turned away.
type resumeField struct{ Name, Value string }

// resumable is the submission to replay once the passkey has been used.
type resumable struct {
	Action    string
	CSRFScope string
	Fields    []resumeField
}

// pendingSubmission preserves the form that triggered the reauthentication so
// the ceremony can finish the job the user actually asked for. Without it the
// bounce is quietly destructive: the ceremony succeeds, the browser lands on a
// freshly rendered page, and everything typed into the form is gone with
// nothing on screen to say so.
//
// Only ordinary form posts are carried. A JSON fetch or a multipart upload
// cannot be rebuilt out of hidden inputs, and reading either body here would
// consume it before the handler that follows ever sees it.
func pendingSubmission(w http.ResponseWriter, r *http.Request) *resumable {
	if r.Method != http.MethodPost {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil
	}
	// Several handlers reach requireRecent before setting their own cap, so
	// the cap is applied here too rather than trusting the caller's order.
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err = r.ParseForm(); err != nil {
		return nil
	}
	pending := &resumable{Action: relativeRequestURI(r), CSRFScope: "account"}
	if strings.HasPrefix(r.URL.Path, "/admin/") {
		pending.CSRFScope = "admin-clients"
	}
	for name, values := range r.PostForm {
		// The posted token is bound to the session the ceremony is about to
		// replace, so it is dropped and a live one is stamped in on success.
		if name == "csrf" {
			continue
		}
		for _, value := range values {
			pending.Fields = append(pending.Fields, resumeField{Name: name, Value: value})
		}
	}
	sort.Slice(pending.Fields, func(i, j int) bool {
		if pending.Fields[i].Name != pending.Fields[j].Name {
			return pending.Fields[i].Name < pending.Fields[j].Name
		}
		return pending.Fields[i].Value < pending.Fields[j].Value
	})
	return pending
}

// reauthTarget is where to land after the ceremony. A GET can simply be
// repeated; a POST cannot, so it falls back to the page the form was on.
func reauthTarget(r *http.Request) string {
	if r.Method == http.MethodGet {
		return relativeRequestURI(r)
	}
	if referer, err := url.Parse(r.Referer()); err == nil && referer.Path != "" && referer.Host == r.Host {
		return safeReturnPath(referer.RequestURI())
	}
	return "/account"
}

func (a *App) profileUpdate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	_ = r.ParseForm()
	if !security.ValidateCSRF(session.RawToken, "account", r.Form.Get("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	name := strings.TrimSpace(r.Form.Get("display_name"))
	var namePtr *string
	if name != "" {
		if len([]rune(name)) > 100 {
			http.Error(w, "display name too long", 400)
			return
		}
		namePtr = &name
	}
	if err := a.Store.UpdateDisplayName(r.Context(), session.User.ID, namePtr); err != nil {
		http.Error(w, "could not update profile", 500)
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
	current := ""
	if session.User.Email != nil {
		current = *session.User.Email
	}
	if !strings.EqualFold(email, current) {
		if !a.requireRecent(w, r, session) {
			return
		}
		if email == "" {
			if err := a.Store.DeleteEmail(r.Context(), session.User.ID); err != nil {
				http.Error(w, "could not remove email", 500)
				return
			}
			if session.User.EmailVerified && current != "" {
				sendAsync(r.Context(), func(ctx context.Context) error {
					return a.Mailer.Send(ctx, current, "Claustra recovery email removed", "The recovery email was removed from your Claustra account. If this was not you, sign in with a registered passkey and add a verified address.")
				}, a.Logger.Error)
			}
		} else {
			normalized, err := normalizeEmail(email)
			if err != nil {
				http.Error(w, "invalid email address", 400)
				return
			}
			token, err := security.RandomToken(32)
			if err != nil {
				http.Error(w, "could not update email", 500)
				return
			}
			if err = a.Store.PutEmailToken(r.Context(), session.User.ID, "verify", email, store.HashSecret(token), time.Now().Add(time.Hour)); err != nil {
				http.Error(w, "could not update email", 500)
				return
			}
			link := a.Config.Issuer + "/email/verify?token=" + url.QueryEscape(token)
			// Every other message in Claustra is sent through sendAsync and a
			// failure only reaches the log. This one is reported, because the
			// address stays inactive until its link is opened and a silent
			// success would leave the account looking like it has recovery it
			// does not. 503, not 502: the request was fine and the origin is
			// healthy - a 502 from here is indistinguishable from the proxy
			// in front having failed.
			if err = a.Mailer.Send(r.Context(), email, "Verify your Claustra email", "Open this one-time link within one hour:\n\n"+link+"\n\nIf you did not request this, ignore the message."); err != nil {
				a.Logger.Error("send verification email", "error", err)
				a.render(w, http.StatusServiceUnavailable, "message", map[string]any{
					"Title": "Email not sent", "SignedIn": true, "Admin": session.Admin, "LogoutCSRF": security.CSRF(session.RawToken, "account"),
					"Back": "/account", "BackLabel": "Back to your account",
					"Heading": "Verification email could not be sent",
					"Message": "Your display name was saved. The address was not added: it becomes active only once its verification link is opened, and that message could not be sent right now.",
				})
				return
			}
			_ = normalized
		}
	}
	a.Store.Audit(r.Context(), "profile.updated", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), nil)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func normalizeEmail(value string) (string, error) {
	parsed, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil || parsed.Address != strings.TrimSpace(value) {
		return "", fmt.Errorf("invalid email")
	}
	at := strings.LastIndex(parsed.Address, "@")
	if at < 1 {
		return "", fmt.Errorf("invalid email")
	}
	return strings.ToLower(parsed.Address[:at]) + "@" + strings.ToLower(parsed.Address[at+1:]), nil
}

func (a *App) emailVerify(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	userID, email, err := a.Store.ConsumeEmailToken(r.Context(), store.HashSecret(raw), "verify")
	if err != nil {
		http.Error(w, "verification link is invalid or expired", 400)
		return
	}
	normalized, err := normalizeEmail(email)
	if err != nil {
		http.Error(w, "invalid email", 400)
		return
	}
	previous, _ := a.Store.UserByID(r.Context(), userID)
	if err = a.Store.VerifyEmail(r.Context(), userID, email, normalized); err != nil {
		http.Error(w, "email address is already used by another account", 409)
		return
	}
	if previous.EmailVerified && previous.Email != nil && !strings.EqualFold(*previous.Email, email) {
		old := *previous.Email
		sendAsync(r.Context(), func(ctx context.Context) error {
			return a.Mailer.Send(ctx, old, "Claustra recovery email changed", "The recovery email on your Claustra account was changed. If this was not you, sign in with a registered passkey and correct it.")
		}, a.Logger.Error)
	}
	a.Store.Audit(r.Context(), "email.verified", &userID, &userID, nil, clientIP(r), r.UserAgent(), nil)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (a *App) avatarUpload(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 6<<20)
	if err := r.ParseMultipartForm(6 << 20); err != nil {
		http.Error(w, "image is too large", 400)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !security.ValidateCSRF(session.RawToken, "account", r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	file, _, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "missing image", 400)
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (5<<20)+1))
	if err != nil || len(raw) > 5<<20 {
		http.Error(w, "image is too large", 400)
		return
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		http.Error(w, "unsupported image", 400)
		return
	}
	bounds := img.Bounds()
	if bounds.Dx() > 4096 || bounds.Dy() > 4096 || bounds.Dx() < 1 || bounds.Dy() < 1 {
		http.Error(w, "invalid image dimensions", 400)
		return
	}
	img = resizeWithin(img, 512, 512)
	var out bytes.Buffer
	if err = png.Encode(&out, img); err != nil {
		http.Error(w, "could not process image", 500)
		return
	}
	if _, err = a.Store.PutAvatar(r.Context(), session.User.ID, "image/png", out.Bytes()); err != nil {
		http.Error(w, "could not store image", 500)
		return
	}
	a.Store.Audit(r.Context(), "avatar.updated", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), nil)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func resizeWithin(src image.Image, maxW, maxH int) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= maxW && h <= maxH {
		return src
	}
	scaleW := float64(maxW) / float64(w)
	scaleH := float64(maxH) / float64(h)
	scale := scaleW
	if scaleH < scale {
		scale = scaleH
	}
	nw, nh := int(float64(w)*scale), int(float64(h)*scale)
	dst := image.NewNRGBA(image.Rect(0, 0, nw, nh))
	for y := 0; y < nh; y++ {
		sy := b.Min.Y + y*h/nh
		for x := 0; x < nw; x++ {
			sx := b.Min.X + x*w/nw
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}

func sendAsync(ctx context.Context, sender func(context.Context) error, logger func(string, ...any)) {
	go func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if err := sender(c); err != nil {
			logger("email send failed", "error", err)
		}
	}()
}

// accountAvatar serves the signed-in user their own picture. The OIDC /avatar
// endpoint stays token-only; this one is authorized by the session cookie.
func (a *App) accountAvatar(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	media, picture, version, err := a.Store.Avatar(r.Context(), session.User.ID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Set("ETag", "\""+version.String()+"\"")
	_, _ = w.Write(picture)
}
