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
	"net/http"
	"net/mail"
	"net/url"
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
	a.render(w, 200, "account", map[string]any{"Title": "Account", "SignedIn": true, "NavAccount": true, "HasAvatar": a.Store.HasAvatar(r.Context(), session.User.ID), "User": session.User, "Admin": session.Admin, "CSRF": security.CSRF(session.RawToken, "account"), "PendingRecovery": pending, "RecoveryID": recoveryID, "RecoveryDue": recoveryDue, "Sessions": sessionViews, "Consents": consents})
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
	_ = a.Store.RevokeSession(r.Context(), session.Session.Hash)
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
	_ = a.Store.RevokeAllSessions(r.Context(), session.User.ID)
	a.clearSessionCookie(w)
	a.Store.Audit(r.Context(), "sessions.revoked_all", &session.User.ID, &session.User.ID, nil, clientIP(r), r.UserAgent(), nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) requireRecent(w http.ResponseWriter, r *http.Request, session sessionContext) bool {
	if time.Since(session.Session.AuthTime) > 5*time.Minute {
		http.Error(w, "Fresh passkey authentication required. Sign out and sign in again.", http.StatusForbidden)
		return false
	}
	return true
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
					"Title": "Email not sent", "SignedIn": true, "Admin": session.Admin,
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
