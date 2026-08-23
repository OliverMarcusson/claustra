package server

const pageTemplates = `
{{define "head"}}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>{{if .Title}}{{.Title}} · {{end}}Claustra</title>
<link rel="stylesheet" href="{{asset "/static/claustra.css"}}">
<link rel="icon" href="{{asset "/static/mark.svg"}}" type="image/svg+xml">
</head>
<body>
<header class="site-header"><div class="site-header__inner">
  <a class="brand" href="/"><span class="brand__mark">{{template "icon-lock-open"}}</span>Claustra</a>
  <nav class="site-nav">
    {{if .SignedIn}}
      <a href="/account"{{if .NavAccount}} aria-current="page"{{end}}>Account</a>
      {{if .Admin}}<a href="/admin/clients"{{if .NavAdmin}} aria-current="page"{{end}}>Admin</a>{{end}}
      {{if .LogoutCSRF}}<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.LogoutCSRF}}"><button class="site-nav__signout">Sign out</button></form>{{end}}
    {{else}}
      <a href="/login">Sign in</a>
      <a href="/register">Create account</a>
    {{end}}
  </nav>
</div></header>
<main class="shell">{{end}}

{{define "foot"}}</main>
<footer class="site-footer"><div class="shell">
  <span>Claustra</span>
  <a class="push" href="/.well-known/openid-configuration">Discovery</a>
  <a href="/recover">Recover account</a>
</div></footer>
</body></html>{{end}}

{{define "icon-lock-open"}}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2.5"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path><circle cx="12" cy="16.5" r="1.1" fill="currentColor" stroke="none"></circle></svg>{{end}}
{{define "icon-key"}}<svg class="row__glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="4.5"></circle><path d="M10.7 12.3 21 2m-4 4 2.5 2.5M14 5l2.5 2.5"></path></svg>{{end}}
{{define "icon-device"}}<svg class="row__glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="4" width="20" height="13" rx="2"></rect><path d="M8 21h8m-4-4v4"></path></svg>{{end}}
{{define "icon-app"}}<svg class="row__glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="2"></rect><rect x="14" y="3" width="7" height="7" rx="2"></rect><rect x="3" y="14" width="7" height="7" rx="2"></rect><rect x="14" y="14" width="7" height="7" rx="2"></rect></svg>{{end}}
{{define "icon-user"}}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"></circle><path d="M4.5 20a7.5 7.5 0 0 1 15 0"></path></svg>{{end}}
{{define "icon-mail"}}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="m3.5 7 8.5 6 8.5-6"></path></svg>{{end}}
{{define "icon-globe"}}<svg class="row__glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3Z"></path></svg>{{end}}
{{define "icon-shield"}}<svg class="row__glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7.5 3v5.5c0 4.4-3 8.3-7.5 9.5-4.5-1.2-7.5-5.1-7.5-9.5V6Z"></path><path d="m9 12 2 2 4-4"></path></svg>{{end}}
{{define "login-button-lock"}}<svg class="claustra-login__lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2.5"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path><circle cx="12" cy="16.5" r="1.1" fill="currentColor" stroke="none"></circle></svg>{{end}}

{{define "message"}}{{template "head" .}}
<div class="center">
  <h1>{{.Heading}}</h1>
  <p class="lede">{{.Message}}</p>
  <div class="row-actions"><a class="btn" href="{{if .Back}}{{.Back}}{{else}}/{{end}}">{{if .BackLabel}}{{.BackLabel}}{{else}}Back to Claustra{{end}}</a></div>
</div>
{{template "foot" .}}{{end}}

{{define "denied"}}{{template "head" .}}
<div class="center">
  <h1>No access to {{.Service}}</h1>
  <p class="lede">{{.Service}} admits only specific accounts, and this one is not among them.</p>
  {{if .Email}}
    <p class="faint">You are signed in as <strong>{{.Email}}</strong>. If you have another account that should have access, sign out and use that one; otherwise ask the administrator to add this address.</p>
  {{else}}
    <p class="faint">This account has no verified email address. A service allowlist matches on verified addresses only, so an unverified one never grants access. Add and verify an address on your account, then try again.</p>
  {{end}}
  <div class="row-actions">
    <a class="btn" href="/account">Your account</a>
    {{if .LogoutCSRF}}<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.LogoutCSRF}}"><button class="btn btn--danger">Sign out</button></form>{{end}}
  </div>
</div>
{{template "foot" .}}{{end}}

{{define "home"}}{{template "head" .}}
{{if .SignedIn}}
<section class="section">
  <div class="identity">
    <span class="avatar avatar--placeholder">{{template "icon-user"}}</span>
    <div class="identity__text">
      <span class="identity__name">{{if .User.DisplayName}}{{.User.WebAuthnDisplayName}}{{else}}Your Claustra account{{end}}</span>
      <span class="badge badge--ok">Session active</span>
    </div>
  </div>
  <div class="row-actions row-actions--spaced">
    <a class="btn btn--primary" href="/account">Account</a>
    {{if .Admin}}<a class="btn" href="/admin/clients">Administration</a>{{end}}
  </div>
</section>
{{else}}
<section class="hero">
  <h1>One passkey. Your whole identity.</h1>
  <p class="lede">Sign in to connected services with the passkey already on your device.</p>
  <a class="claustra-login" href="/login"><span class="claustra-login__label">Sign in with Claustra</span>{{template "login-button-lock"}}</a>
  <div class="row-actions"><a class="btn btn--quiet" href="/register">Create account</a><a class="btn btn--quiet" href="/recover">Recover account</a></div>
</section>
{{end}}
{{template "foot" .}}{{end}}

{{define "passkey"}}{{template "head" .}}
<div class="center">
  <div class="page-head"><h1>{{.Heading}}</h1><p class="lede">{{.Description}}</p></div>
  <button class="claustra-login" id="passkey" data-begin="{{.Begin}}" data-finish="{{.Finish}}" data-method="{{.Method}}" data-continue="{{.Continue}}" data-bootstrap="{{.Bootstrap}}"><span class="claustra-login__label">{{.Button}}</span>{{template "login-button-lock"}}</button>
  <p class="status" id="status" role="status"></p>
</div>
<script src="{{asset "/static/passkey.js"}}" defer></script>
{{template "foot" .}}{{end}}

{{define "consent"}}{{template "head" .}}
<div class="center">
  <div class="page-head">
    <span class="eyebrow">Authorization request</span>
    <h1>{{.Client.Name}} wants to sign you in</h1>
  </div>
  <ul class="scopes">
    {{if hasScope .Scopes "openid"}}<li>{{template "icon-shield"}}<span>Your app-specific Claustra identifier.</span></li>{{end}}
    {{if hasScope .Scopes "profile"}}<li>{{template "icon-user"}}<span>Your display name and profile picture.</span></li>{{end}}
    {{if hasScope .Scopes "email"}}<li>{{template "icon-mail"}}<span>Your verified email address.</span></li>{{end}}
  </ul>
  <form method="post" action="/authorize/consent">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    {{range $k,$v:=.Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
    <button class="btn btn--primary btn--block" name="decision" value="allow">Allow and continue</button>
    <button class="btn btn--quiet btn--block" name="decision" value="deny">Cancel</button>
  </form>
  {{if .Client.HomepageURI}}<p class="faint">{{.Client.HomepageURI}}{{if .Client.PrivacyPolicyURI}} · <a href="{{.Client.PrivacyPolicyURI}}" rel="noreferrer">Privacy policy</a>{{end}}</p>{{end}}
</div>
{{template "foot" .}}{{end}}

{{define "account"}}{{template "head" .}}
{{if .PendingRecovery}}
<div class="notice">
  <div class="notice__head"><h2>Recovery in progress</h2><span class="badge badge--warn">Quarantined</span></div>
  <p class="faint">A replacement passkey completes at {{fmtTime .RecoveryDue}}.</p>
  <form method="post" action="/recovery/cancel">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="recovery_id" value="{{.RecoveryID}}">
    <div class="row-actions"><button class="btn btn--danger btn--sm">Cancel recovery</button></div>
  </form>
</div>
{{end}}

<section class="section">
  <div class="identity">
    {{if .HasAvatar}}<img class="avatar" src="/account/avatar" alt="Your profile picture" width="64" height="64">
    {{else}}<span class="avatar avatar--placeholder">{{template "icon-user"}}</span>{{end}}
    <div class="identity__text">
      <span class="identity__name">{{if .User.DisplayName}}{{.User.WebAuthnDisplayName}}{{else}}Unnamed account{{end}}</span>
      <div class="row-actions">
        {{if .User.Email}}{{if .User.EmailVerified}}<span class="badge badge--ok">Email verified</span>{{else}}<span class="badge badge--warn">Verification pending</span>{{end}}
        {{else}}<span class="badge badge--off">No recovery email</span>{{end}}
        {{if .Admin}}<span class="badge badge--accent">Administrator</span>{{end}}
      </div>
      <p class="faint">{{.User.ID}}</p>
    </div>
  </div>
</section>

<section class="section">
  <div class="section__head"><h2>Profile</h2></div>
  <form method="post" action="/profile">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label class="field"><span>Display name</span><input name="display_name" value="{{if .User.DisplayName}}{{.User.WebAuthnDisplayName}}{{end}}" maxlength="100" placeholder="Optional"></label>
    <label class="field"><span>Email</span><input name="email" type="email" value="{{if .User.Email}}{{.User.Email}}{{end}}" placeholder="Optional"></label>
    <div class="row-actions"><button class="btn btn--primary">Save profile</button></div>
  </form>
  <form method="post" action="/profile/avatar" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label class="field"><span>Profile picture</span><input type="file" name="avatar" accept="image/png,image/jpeg,image/gif"><small>PNG, JPEG, or GIF, up to 5 MB.</small></label>
    <div class="row-actions"><button class="btn">Upload picture</button></div>
  </form>
</section>

<section class="section">
  <div class="section__head"><h2>Passkeys</h2><a class="btn btn--sm push" href="/account/passkeys/add">Add passkey</a></div>
  <div class="rows">
    {{range .User.Credentials}}{{if eq .State "active"}}
    <div class="row">
      {{template "icon-key"}}
      <div class="row__main">
        <span class="row__title">{{if .Name}}{{.Name}}{{else}}Passkey{{end}}</span>
        <span class="row__meta">Added {{fmtTime .CreatedAt}} · last used {{fmtTime .LastUsedAt}}</span>
      </div>
      <form method="post" action="/account/passkeys/revoke">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <input type="hidden" name="credential_id" value="{{.ID}}">
        <button class="btn btn--danger btn--sm">Revoke</button>
      </form>
    </div>
    {{end}}{{end}}
  </div>
</section>

<section class="section">
  <div class="section__head"><h2>Sessions</h2></div>
  <div class="rows">
    {{range .Sessions}}
    <div class="row">
      {{template "icon-device"}}
      <div class="row__main">
        <span class="row__title">{{if .IP}}{{.IP}}{{else}}Unknown address{{end}}{{if .Current}} <span class="badge badge--ok">This device</span>{{end}}</span>
        <span class="row__meta">{{.UserAgent}} · last seen {{fmtTime .LastSeen}}</span>
      </div>
      <form method="post" action="/account/sessions/revoke">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <input type="hidden" name="session" value="{{.Hash}}">
        <button class="btn btn--danger btn--sm">Revoke</button>
      </form>
    </div>
    {{else}}<p class="empty">No active sessions.</p>{{end}}
  </div>
  <div class="row-actions row-actions--spaced">
    <form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn">Sign out here</button></form>
    <form method="post" action="/logout/all"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn">Sign out everywhere</button></form>
  </div>
</section>

<section class="section">
  <div class="section__head"><h2>Connected apps</h2></div>
  <div class="rows">
    {{range .Consents}}
    <div class="row">
      {{template "icon-app"}}
      <div class="row__main">
        <span class="row__title">{{.ClientName}}</span>
        <span class="row__meta">{{range .Scopes}}{{.}} {{end}}· granted {{fmtTime .GrantedAt}}</span>
      </div>
      <form method="post" action="/account/consents/revoke">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <input type="hidden" name="client_id" value="{{.ClientID}}">
        <button class="btn btn--danger btn--sm">Revoke</button>
      </form>
    </div>
    {{else}}<p class="empty">No app permissions granted.</p>{{end}}
  </div>
</section>

<section class="section section--danger">
  <div class="section__head"><h2>Delete account</h2></div>
  <p class="faint">The account is disabled immediately and erased after seven days. A passkey or the verified email can cancel it during that window.</p>
  <form method="post" action="/account/delete" class="spaced">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="row-actions"><button class="btn btn--danger">Delete this account</button></div>
  </form>
</section>
{{template "foot" .}}{{end}}

{{define "reauth"}}{{template "head" .}}
<div class="center">
  <div class="page-head">
    <h1>Confirm it is you</h1>
    <p class="lede">Changing passkeys, email, roles or clients needs a passkey used in the last five minutes.</p>
  </div>
  <button class="claustra-login" id="passkey" data-begin="/webauthn/login/begin" data-finish="/webauthn/login/finish" data-method="get" data-continue="{{.Continue}}" data-bootstrap="" data-csrf-scope="{{with .Resume}}{{.CSRFScope}}{{end}}"><span class="claustra-login__label">Use your passkey</span>{{template "login-button-lock"}}</button>
  <p class="status" id="status" role="status"></p>
  <p class="faint">You stay signed in - this only proves the passkey is still in your hands, and returns you to what you were doing.</p>
{{with .Resume}}  <form method="post" action="{{.Action}}" id="resume" hidden>
    <input type="hidden" name="csrf" value="">
    {{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
    {{end}}</form>
{{end}}</div>
<script src="{{asset "/static/passkey.js"}}" defer></script>
{{template "foot" .}}{{end}}

{{define "recover"}}{{template "head" .}}
<div class="center">
  <div class="page-head"><h1>Recover account</h1><p class="lede">Recovery requires a verified email and waits 24 hours before replacing existing passkeys.</p></div>
  <form method="post">
    <label class="field"><span>Email</span><input name="email" type="email" required placeholder="you@example.com"></label>
    <button class="btn btn--primary btn--block">Send recovery link</button>
  </form>
  {{if .Sent}}<p class="status">If that address belongs to an account, a recovery link has been sent.</p>{{end}}
</div>
{{template "foot" .}}{{end}}

{{define "admin_clients"}}{{template "head" .}}
{{if .NewSecret}}
<div class="notice">
  <div class="notice__head"><h2>New client secret</h2><span class="badge badge--warn">Shown once</span></div>
  <pre class="secret">{{.NewSecret}}</pre>
  <p class="faint">Claustra stores only a hash of it.</p>
</div>
{{end}}

<section class="section">
  <div class="section__head"><h2>OIDC clients</h2></div>
  <div class="table-wrap"><table>
    <thead><tr><th>Client ID</th><th>Name</th><th>Status</th><th>Access</th><th></th></tr></thead>
    <tbody>
    {{range .Clients}}
      <tr>
        <td><code>{{.ID}}</code></td>
        <td>{{.Name}} {{if .Trusted}}<span class="badge badge--accent">Trusted</span>{{end}}</td>
        <td>{{if .Enabled}}<span class="badge badge--ok">Enabled</span>{{else}}<span class="badge badge--off">Disabled</span>{{end}}</td>
        <td>{{if .Gated}}<span class="badge badge--accent">{{len .AllowedEmails}} allowed</span>{{else}}<span class="badge badge--warn">Any account</span>{{end}}</td>
        <td>
          <div class="row-actions">
            <form method="post" action="/admin/clients/rotate"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="client_id" value="{{.ID}}"><button class="btn btn--sm">Rotate secret</button></form>
            <form method="post" action="/admin/clients/toggle"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="client_id" value="{{.ID}}"><input type="hidden" name="enabled" value="{{if .Enabled}}false{{else}}true{{end}}"><button class="btn btn--sm{{if .Enabled}} btn--danger{{end}}">{{if .Enabled}}Disable{{else}}Enable{{end}}</button></form>
          </div>
        </td>
      </tr>
    {{else}}
      <tr><td colspan="5"><span class="faint">No clients registered.</span></td></tr>
    {{end}}
    </tbody>
  </table></div>
</section>

<section class="section">
  <div class="section__head"><h2>Register a client</h2></div>
  <form method="post">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="form-grid">
      <label class="field"><span>Client ID</span><input name="id" pattern="[a-z0-9][a-z0-9-]{1,62}" required placeholder="euripus"></label>
      <label class="field"><span>Name</span><input name="name" required maxlength="100" placeholder="Euripus"></label>
      <label class="field field--wide"><span>Redirect URI</span><input name="redirect_uri" type="url" required placeholder="https://service.example/callback"><small>Matched exactly.</small></label>
      <label class="field"><span>Homepage</span><input name="homepage_uri" type="url"></label>
      <label class="field"><span>Logo</span><input name="logo_uri" type="url"></label>
      <label class="field"><span>Privacy policy</span><input name="privacy_policy_uri" type="url"></label>
      <label class="field"><span>Allowed scopes</span><input name="scopes" value="openid profile email"></label>
      <label class="field"><span>Who may sign in</span><select name="access_policy"><option value="allowlist" selected>Only listed addresses</option><option value="open">Any Claustra account</option></select></label>
      <label class="field field--wide"><span>Allowed email addresses</span><input name="allowed_emails" placeholder="you@example.com, someone@example.com"><small>Matched against verified addresses only. Leave empty and nobody gets in until you add one.</small></label>
    </div>
    <div class="checks">
      <label class="check"><input type="checkbox" name="trusted" value="yes"> Trusted first-party client</label>
      <label class="check"><input type="checkbox" name="preapprove_profile" value="yes"> Preapprove profile scope</label>
      <label class="check"><input type="checkbox" name="preapprove_email" value="yes"> Preapprove email scope</label>
    </div>
    <div class="row-actions"><button class="btn btn--primary">Register client</button></div>
  </form>
</section>

<section class="section">
  <div class="section__head"><h2>Forward-auth hosts</h2></div>
  <div class="rows">
    {{range .ForwardHosts}}
    <div class="row">
      {{template "icon-globe"}}
      <div class="row__main">
        <span class="row__title">{{.Host}}{{if not .Enabled}} <span class="badge badge--off">Disabled</span>{{end}} {{if .Gated}}<span class="badge badge--accent">{{len .AllowedEmails}} allowed</span>{{else}}<span class="badge badge--warn">Any account</span>{{end}}</span>
        <span class="row__meta">{{.Name}}</span>
      </div>
    </div>
    {{else}}<p class="empty">No hosts registered.</p>{{end}}
  </div>
  <form method="post" action="/admin/forward-hosts">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="form-grid">
      <label class="field"><span>Hostname</span><input name="host" required placeholder="service.marcusson.dev"></label>
      <label class="field"><span>Name</span><input name="name" required placeholder="Service"></label>
      <label class="field"><span>Who may sign in</span><select name="access_policy"><option value="allowlist" selected>Only listed addresses</option><option value="open">Any Claustra account</option></select></label>
      <label class="field field--wide"><span>Allowed email addresses</span><input name="allowed_emails" placeholder="you@example.com"></label>
    </div>
    <div class="row-actions"><button class="btn">Register host</button></div>
  </form>
</section>

<section class="section">
  <div class="section__head"><h2>Service access</h2></div>
  <p class="faint">Anyone can register a Claustra account, so an account is not by itself permission to use a service. A gated service admits only the addresses listed here, and only where the account has verified that address.</p>

  {{range .Clients}}
  <div class="row">
    {{template "icon-app"}}
    <div class="row__main">
      <span class="row__title">{{.Name}} <code>{{.ID}}</code></span>
      <span class="row__meta">
        {{if .Gated}}
          {{if .AllowedEmails}}{{range .AllowedEmails}}<span class="badge">{{.}}</span> {{end}}{{else}}<span class="badge badge--off">Nobody listed</span>{{end}}
        {{else}}<span class="badge badge--warn">Open to any Claustra account</span>{{end}}
      </span>
    </div>
  </div>
  <form method="post" action="/admin/clients/access" class="row-actions row-actions--spaced">
    <input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="client_id" value="{{.ID}}">
    <input type="hidden" name="action" value="policy"><input type="hidden" name="policy" value="{{if .Gated}}open{{else}}allowlist{{end}}">
    <button class="btn btn--sm">{{if .Gated}}Open to everyone{{else}}Restrict to a list{{end}}</button>
  </form>
  <form method="post" action="/admin/clients/access" class="form-grid">
    <input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="client_id" value="{{.ID}}"><input type="hidden" name="action" value="allow">
    <label class="field"><span>Allow an address</span><input name="email" type="email" required placeholder="you@example.com"></label>
    <div class="row-actions"><button class="btn btn--sm">Add</button></div>
  </form>
  {{if .AllowedEmails}}
  <div class="row-actions row-actions--spaced">
    {{$cid := .ID}}
    {{range .AllowedEmails}}
    <form method="post" action="/admin/clients/access">
      <input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="client_id" value="{{$cid}}"><input type="hidden" name="action" value="deny"><input type="hidden" name="email" value="{{.}}">
      <button class="btn btn--sm btn--danger">Remove {{.}}</button>
    </form>
    {{end}}
  </div>
  {{end}}
  {{else}}<p class="empty">No clients registered.</p>{{end}}

  {{range .ForwardHosts}}
  <div class="row">
    {{template "icon-globe"}}
    <div class="row__main">
      <span class="row__title">{{.Host}}</span>
      <span class="row__meta">
        {{if .Gated}}
          {{if .AllowedEmails}}{{range .AllowedEmails}}<span class="badge">{{.}}</span> {{end}}{{else}}<span class="badge badge--off">Nobody listed</span>{{end}}
        {{else}}<span class="badge badge--warn">Open to any Claustra account</span>{{end}}
      </span>
    </div>
  </div>
  <form method="post" action="/admin/forward-hosts/access" class="row-actions row-actions--spaced">
    <input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="host" value="{{.Host}}">
    <input type="hidden" name="action" value="policy"><input type="hidden" name="policy" value="{{if .Gated}}open{{else}}allowlist{{end}}">
    <button class="btn btn--sm">{{if .Gated}}Open to everyone{{else}}Restrict to a list{{end}}</button>
  </form>
  <form method="post" action="/admin/forward-hosts/access" class="form-grid">
    <input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="host" value="{{.Host}}"><input type="hidden" name="action" value="allow">
    <label class="field"><span>Allow an address</span><input name="email" type="email" required placeholder="you@example.com"></label>
    <div class="row-actions"><button class="btn btn--sm">Add</button></div>
  </form>
  {{if .AllowedEmails}}
  <div class="row-actions row-actions--spaced">
    {{$h := .Host}}
    {{range .AllowedEmails}}
    <form method="post" action="/admin/forward-hosts/access">
      <input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="host" value="{{$h}}"><input type="hidden" name="action" value="deny"><input type="hidden" name="email" value="{{.}}">
      <button class="btn btn--sm btn--danger">Remove {{.}}</button>
    </form>
    {{end}}
  </div>
  {{end}}
  {{end}}
</section>

<section class="section">
  <div class="section__head"><h2>Administrators</h2></div>
  <div class="rows">
    {{range .Admins}}
    <div class="row">
      {{template "icon-shield"}}
      <div class="row__main">
        <span class="row__title">{{if .DisplayName}}{{.DisplayName}}{{else}}Unnamed account{{end}}</span>
        <span class="row__meta">{{if .Email}}{{.Email}} · {{end}}{{.UserID}}</span>
      </div>
      <form method="post" action="/admin/roles">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <input type="hidden" name="user_id" value="{{.UserID}}">
        <input type="hidden" name="admin" value="false">
        <button class="btn btn--danger btn--sm">Remove</button>
      </form>
    </div>
    {{else}}<p class="empty">No administrators.</p>{{end}}
  </div>
  <form method="post" action="/admin/roles">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="admin" value="true">
    <label class="field"><span>User ID</span><input name="user_id" required placeholder="00000000-0000-0000-0000-000000000000"></label>
    <div class="row-actions"><button class="btn">Add administrator</button></div>
  </form>
</section>

<section class="section">
  <div class="section__head"><h2>Sign-in button</h2><a class="btn btn--sm push" href="/static/claustra-button.css">claustra-button.css</a></div>
  <a class="claustra-login" href="/login"><span class="claustra-login__label">Log in with Claustra</span>{{template "login-button-lock"}}</a>
  <pre class="spaced">&lt;link rel="stylesheet" href="{{.Issuer}}/static/claustra-button.css"&gt;

&lt;a class="claustra-login" href="/auth/claustra/start"&gt;
  &lt;span class="claustra-login__label"&gt;Log in with Claustra&lt;/span&gt;
  &lt;svg class="claustra-login__lock" viewBox="0 0 24 24" fill="none" stroke="currentColor"
       stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"&gt;
    &lt;rect x="3" y="11" width="18" height="11" rx="2.5"/&gt;
    &lt;path d="M7 11V7a5 5 0 0 1 9.9-1"/&gt;
    &lt;circle cx="12" cy="16.5" r="1.1" fill="currentColor" stroke="none"/&gt;
  &lt;/svg&gt;
&lt;/a&gt;</pre>
</section>
{{template "foot" .}}{{end}}
`
