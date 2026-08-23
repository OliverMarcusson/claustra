# Claustra

> Revised design · 23 August 2026 · Version 2

Claustra is a passkey-first identity provider for Oliver's services. It gives services a standard **Sign in with Claustra** flow and keeps authentication, profile sharing, recovery, sessions, and revocation in one place.

The permanent issuer and authentication origin is:

```text
https://claustra.marcusson.dev
```

Claustra is, precisely, an **OpenID Connect Provider** and an **OAuth 2.0 Authorization Server**. OAuth alone delegates access to APIs; OpenID Connect (OIDC) adds the signed identity assertion needed for social login. OIDC is therefore the core protocol from the first usable release. Caddy forward-auth remains an adapter for services that cannot speak OIDC.

The user interface is deliberately out of scope for this revision. Initial pages may be plain, accessible forms and status screens.

## 1. Product boundaries

- Anyone may create a Claustra account.
- Every account begins with a discoverable passkey. Claustra has no passwords.
- Accounts do not need a username, display name, avatar, or email address.
- An administrator, not the public, registers client applications. This permits third-party applications without hardcoding Claustra to a fixed list of Oliver's services.
- A client becomes usable as soon as an administrator saves it.
- Claustra has no public directory, searchable profiles, or public profile pages.
- Server-backed websites are the only client type in the first release. Browser-only apps, native apps, CLIs, device authorization, and general API delegation are deferred.
- Claustra is deployed as a single-server personal service. It is not presented as a general public identity utility, even though account registration is open.

## 2. Identity and privacy model

The internal user ID is random, immutable, and never reused. Applications never use an email address or display name as an account key.

Each client receives a different stable **pairwise subject identifier** in the OIDC `sub` claim. Two unrelated clients therefore cannot correlate the same person by comparing Claustra IDs. Pairwise subjects survive profile and email changes. If an account is deleted and recreated, it receives new subjects.

Claims are deliberately small:

| Scope | Claims | Rule |
| --- | --- | --- |
| `openid` | `sub` | Required for login; opaque and pairwise per client |
| `profile` | `name`, `picture` | Included only when the user has supplied the field and granted the scope |
| `email` | `email`, `email_verified` | Included only for a verified address after consent |

There is no public username. The optional display name is descriptive, non-unique, and mutable. Clients must not treat it as an identifier.

An uploaded avatar is decoded, size-limited, resized, re-encoded, and stripped of metadata before storage. It is stored in Postgres with the account rather than on an independently backed-up filesystem. The `picture` URL requires an access token carrying `profile`; knowing the URL alone does not expose the image.

One verified email address may belong to only one account. Claustra normalizes addresses consistently for uniqueness. A change requires verification of the new address, a fresh passkey assertion, and a notification to the old address. Claustra emits `email_verified: true` only after the verification link has been completed.

## 3. Registration and passkeys

Registration is available both on Claustra itself and within an application's authorization flow. After registration, the browser returns to the requesting application and resumes authorization.

The registration sequence is:

1. Create a short-lived, single-use WebAuthn challenge tied to the browser transaction.
2. Create a discoverable credential with user verification required.
3. Store the credential public key and authenticator metadata.
4. Create the account and its first Claustra session in one transaction.
5. Offer optional display name, avatar, and email enrollment without blocking login.
6. If registration began at `/authorize`, continue to consent and then return to the client.

WebAuthn policy:

- RP ID: `claustra.marcusson.dev`
- Allowed origin: `https://claustra.marcusson.dev`
- Discoverable credentials: required
- User verification: required
- Attestation: none
- Platform, roaming, device-bound, and synced passkeys: accepted
- Multiple passkeys per account: supported and encouraged

Only Claustra performs WebAuthn ceremonies. Client services never receive credential identifiers or assertion material. Using the narrower Claustra hostname as the RP ID avoids granting every `marcusson.dev` subdomain a role in the WebAuthn security boundary.

Challenges are random, expire quickly, are bound to one operation and browser transaction, and are consumed once. Signature counters and backup flags are recorded for audit and risk signals, but a zero or non-increasing counter alone does not lock out a user because synced passkeys do not provide a reliable global counter.

The passkey's internal WebAuthn user handle is opaque. When no display name exists, authenticator UI may label it simply as a Claustra account; identity never depends on that label.

## 4. OpenID Connect flow

Version 1 implements only the **Authorization Code Flow with PKCE** for confidential, server-backed web clients.

1. The client creates `state`, `nonce`, and a PKCE verifier and challenge.
2. It redirects the browser to `/authorize` with `response_type=code`, `scope=openid`, an exact registered redirect URI, and the PKCE challenge.
3. Claustra authenticates the user with an existing SSO session or a passkey.
4. Claustra applies the client's trust policy and obtains consent when necessary.
5. Claustra returns a short-lived, single-use authorization code to the exact redirect URI.
6. The client's backend authenticates at `/token` and exchanges the code with its PKCE verifier.
7. Claustra returns a signed ID token and a short-lived opaque access token.
8. The client validates issuer, audience, signature, expiry, and nonce, then creates its own local application session.

Security rules:

- PKCE with `S256` is mandatory even for confidential clients.
- Redirect URIs use exact string matching and HTTPS. Wildcards and open redirects are forbidden.
- `state` protects the client transaction; `nonce` binds the ID token to it.
- Authorization codes expire after 60 seconds, are single-use, and are bound to the client, redirect URI, and PKCE challenge.
- ID tokens expire after 5 minutes and are never used as long-lived application sessions.
- Opaque access tokens expire after 15 minutes and are accepted only by Claustra's UserInfo and protected-avatar endpoints.
- Refresh tokens, implicit flow, resource-owner password flow, client credentials, token exchange, DPoP, PAR, and device authorization are not implemented initially.
- Client secrets are at least 32 random bytes, shown only when created or rotated, and stored as hashes. Multiple secrets may overlap briefly for safe rotation.

ID tokens are signed with a rotating `RS256` key for broad OIDC client compatibility. JWKS publishes the current public key and retains previous public keys until every token they signed has expired. Private signing keys never enter the public Nix store.

### Standard endpoints

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/openid-configuration` | OIDC discovery metadata |
| `/.well-known/oauth-authorization-server` | OAuth authorization-server metadata |
| `/authorize` | Authentication, registration, and consent |
| `/token` | Authorization-code exchange |
| `/userinfo` | Claims authorized by the access token |
| `/avatar` | Processed profile image authorized by `profile` |
| `/jwks.json` | Public token-verification keys |
| `/revoke` | Access-token revocation |
| `/logout` | Claustra session and RP-initiated logout entry point |

The protocol follows OpenID Connect Core and Discovery, OAuth authorization-server metadata, PKCE, and the OAuth 2.0 Security Best Current Practice. Claustra should use a maintained OIDC/OAuth library for parsing, validation, and token plumbing rather than inventing protocol or cryptographic primitives.

References:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
- [Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636.html)
- [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)

## 5. Clients and consent

Only an administrator can create, edit, disable, or rotate credentials for a client. Client registration is database-backed rather than compiled into Claustra.

A client record contains:

- name and optional logo;
- homepage and privacy-policy URL;
- exact redirect URIs;
- hashed client secrets and rotation metadata;
- allowed scopes;
- trusted/first-party status and preapproved scopes;
- enabled/disabled state;
- creator, creation time, and last modification audit data.

Trusted first-party clients may skip consent for administrator-preapproved scopes. Other clients show a plain prompt such as: **Euripus wants your name, profile picture, and verified email address.** Consent is requested again if the client later asks for additional data.

Consent records include the user, client, granted scopes, client-policy version, and timestamps. Users can inspect and revoke client access from their account page. Revocation invalidates active Claustra access tokens and future silent grants. It cannot erase information the client already received or end a session held solely by that client; the UI must state this honestly.

## 6. Sessions and logout

The Claustra SSO cookie is host-only, `Secure`, `HttpOnly`, and `SameSite=Lax`, using the `__Host-` prefix. Its random value is stored only as a hash in Postgres.

An SSO session has:

- a 30-day inactivity timeout;
- a 90-day absolute lifetime;
- last-seen, IP, user-agent, creation, and authentication timestamps;
- a reference to the passkey or recovery event that created it.

A fresh passkey assertion is required for passkey management, email changes, account deletion, administration, client management, role changes, and other sensitive operations. New profile claims or expanded consent also require recent authentication.

Signing out of an application normally ends only that application's local session. Claustra provides **sign out everywhere**, which revokes every Claustra SSO session and access token. Full coordinated back-channel logout to every client is deferred; clients remain responsible for their own session lifetime.

Users can view and individually revoke their Claustra sessions and passkeys. Deleting the parent SSO session also invalidates any forward-auth sessions derived from it.

## 7. Email verification and recovery

Email is optional. An account without a verified recovery email is allowed, but Claustra clearly warns that losing all passkeys makes that account unrecoverable.

Verification, recovery, and security notifications use configurable SMTP credentials. Email tokens are random, short-lived, single-use, rate-limited, and stored only as hashes. Recovery requests always return the same public response whether or not an address exists.

Recovery is intentionally slower than normal authentication:

1. The user requests recovery for a verified email address.
2. Claustra sends a one-time link and records the event.
3. The link permits enrollment of one replacement passkey.
4. The replacement enters a 24-hour recovery quarantine. It may access only the recovery status and cancellation surface.
5. Claustra alerts the verified address. Any existing passkey may cancel the recovery during the quarantine.
6. When the delay ends, Claustra activates the replacement, revokes every older passkey, and revokes all sessions and access tokens.
7. Sensitive operations remain blocked until the recovery completes and the user authenticates with the replacement passkey.

This makes verified email a deliberately weaker, delayed recovery factor rather than an instant substitute for a passkey.

## 8. Account deletion

Self-service deletion requires a fresh passkey assertion.

- The account is disabled immediately.
- SSO sessions, access tokens, consents, and normal use of every credential are revoked immediately.
- Credentials and personal data remain disabled for a seven-day undo period.
- Cancellation requires an existing passkey assertion or the verified recovery email. Restoring an account does not restore old sessions or access tokens.
- After seven days, Claustra permanently deletes profile data, email, avatars, credentials, sessions, consents, and recovery material.
- Pairwise subject values are never reassigned. A minimal non-personal tombstone prevents accidental reuse.
- Reduced security-audit records follow their normal retention policy and must not retain deleted profile fields.

Clients are independent data controllers for information they previously received; deleting Claustra cannot automatically delete a user's account or data inside every client. The deletion screen explains this boundary.

## 9. Forward-auth compatibility adapter

OIDC is the source of truth. Forward-auth reuses the same authentication, consent, authorization-code, session, and audit machinery for services that cannot implement OIDC.

For each protected hostname, Caddy routes `/_claustra/*` to Claustra and calls `/forward-auth/verify` before proxying the upstream:

```caddyfile
(claustra) {
    handle /_claustra/* {
        reverse_proxy http://127.0.0.1:13002
    }

    handle {
        forward_auth http://127.0.0.1:13002 {
            uri /forward-auth/verify
            copy_headers X-Claustra-User X-Claustra-Sub
        }
        reverse_proxy {args[0]}
    }
}
```

Each protected host is an administrator-registered internal client with exact callback and return-path rules. A successful callback sets a random `__Host-claustra-rp` cookie on that service's origin; only its hash is stored. The central Claustra SSO cookie is never shared with other subdomains.

Return locations are host-bound relative paths, never caller-supplied absolute URLs. Login redirects are allowed only for top-level `GET` and `HEAD` navigations. API, XHR, and non-idempotent requests receive `401` instead of a login-page redirect. Public API paths such as DNS-over-HTTPS must be matched before the adapter or protected by an API-appropriate bearer-token scheme.

Identity headers are trustworthy only when Caddy strips caller-supplied copies and the upstream is reachable solely through the trusted proxy. Services exposed directly to the LAN or Internet must not trust these headers.

## 10. Administration

An administrator is an ordinary Claustra account with an `admin` role. The first administrator is bootstrapped with a short-lived, one-time CLI enrollment link. Multiple administrators are supported.

Administrators can:

- register, edit, disable, and rotate credentials for clients;
- mark clients as trusted and preapprove specific scopes;
- inspect account status and security events without exposing credential private material;
- disable abusive accounts;
- promote or demote administrators.

Every administrative operation requires recent passkey authentication and creates an audit event. Claustra prevents removal or disabling of the final administrator. Routine support must not provide a way to impersonate a user or bypass the documented email-recovery delay.

## 11. Abuse controls

Open registration means Claustra must tolerate registrations it did not invite.

- Apply per-IP and global rate limits to registration, WebAuthn challenges, email, recovery, token exchange, and failed authorization.
- Require completion of a real passkey registration before creating an active account.
- Introduce a bot challenge only when traffic or rate signals look suspicious; keep the provider replaceable.
- Bound pending challenges, uploads, email attempts, sessions, and accounts created from one network range.
- Make email and account-existence responses indistinguishable.
- Let administrators disable abusive accounts without deleting audit evidence early.

Rate limits are defense in depth, not an identity signal. Shared networks and privacy relays must not permanently lock out legitimate users.

## 12. Data model

Postgres is the authoritative store. Representative tables are:

```text
users                 id · status · display_name · created_at · deleted_at
user_emails           user_id · normalized_email · verified_at · created_at
credentials           id · user_id · credential_id · public_key · sign_count
                      aaguid · transports · backup_state · name · timestamps · revoked_at
avatars               user_id · media_type · bytes · version · created_at
sso_sessions          id_hash · user_id · credential_id · auth_time · created_at
                      last_seen_at · idle_expires_at · absolute_expires_at · ip · user_agent
clients               id · name · metadata · trusted · enabled · timestamps
client_redirect_uris  client_id · redirect_uri
client_secrets        client_id · secret_hash · created_at · expires_at · revoked_at
client_scopes         client_id · scope · preapproved
pairwise_subjects     user_id · client_id · subject
consents              user_id · client_id · scopes · policy_version · timestamps
authorization_codes   code_hash · user_id · client_id · redirect_uri · pkce_challenge
                      nonce · scopes · expires_at · used_at
access_tokens         token_hash · user_id · client_id · scopes · expires_at · revoked_at
webauthn_challenges   challenge_hash · operation · transaction_id · expires_at · used_at
email_tokens          token_hash · user_id · purpose · expires_at · used_at
recoveries            id · user_id · replacement_credential_id · state · completes_at
forward_sessions      id_hash · sso_session_id · user_id · rp_host · expires_at
roles                 user_id · role · granted_by · granted_at
audit_events          id · timestamp · event · actor_user_id · subject_user_id
                      client_id · ip · user_agent · detail
```

Foreign keys, uniqueness constraints, and transactions enforce one-time token use, email uniqueness, subject stability, and revocation cascades. Random session, code, email, and access-token values are stored only as SHA-256 hashes; they already contain enough entropy and are not passwords. Private passkey keys never leave the authenticator—Claustra stores only public keys.

Detailed audit events retain IP address and user agent for 30 days. A scheduled job then removes those fields while retaining reduced event records for one year, after which they are deleted. Security and administrator views respect the same retention policy.

## 13. Service and deployment

Claustra remains a public Go repository and builds as one static application binary. Deployment-specific configuration and all secrets remain private.

- Go with a maintained Postgres driver and embedded transactional migrations
- Postgres on the same single server, with a dedicated database and least-privilege role
- Loopback listener at `127.0.0.1:13002`, exposed only through Caddy
- NixOS module and systemd unit
- Static service user and state directory
- `Restart=on-failure` with a short restart delay
- restrictive systemd sandboxing and no unnecessary capabilities
- SMTP, database, signing, backup, and client-bootstrap secrets supplied through root-readable credentials, never the world-readable Nix store
- health endpoint that checks process readiness and database connectivity without exposing secrets
- metrics suitable for local monitoring, excluding emails, tokens, authorization codes, and credential IDs

Daily encrypted backups include Postgres, OIDC signing keys, and required private deployment configuration. Exactly seven daily generations are retained. Backup encryption keys are stored separately from the backup destination. Restore procedures are documented and periodically tested; an untested backup is not treated as recovery.

Restoring signing keys preserves validation continuity. Restoring an old database can resurrect revoked state, so disaster recovery must invalidate sessions, authorization codes, access tokens, email tokens, and pending recovery operations after a restore.

Claustra is a single point of failure for protected services. A narrowly restricted break-glass path may remain for infrastructure such as AdGuard, but it must not become an undocumented general bypass.

## 14. Security baseline

- TLS is mandatory at the public boundary.
- All state-changing browser requests use CSRF protection and strict origin checks.
- Security headers include a restrictive Content Security Policy, frame denial, MIME sniffing protection, and a conservative referrer policy.
- Database queries are parameterized; schema migrations and one-time state transitions are transactional.
- Logs redact cookies, authorization codes, client secrets, tokens, email links, WebAuthn challenges, and assertions.
- OAuth errors do not disclose secrets or account existence.
- Avatar decoding happens with strict byte, pixel, and format limits.
- Startup fails closed if issuer, origin, RP ID, signing keys, database, or proxy trust configuration is inconsistent.
- Proxy headers are accepted only from the loopback Caddy instance.
- Dependency, protocol, recovery, redirect, CSRF, and authorization tests run during the Nix build; deployment does not disable them.

The highest-risk paths—recovery, redirect validation, token exchange, consent expansion, role changes, and deletion—receive explicit negative and replay tests.

## 15. Rollout

### Phase 0 — Contract and plumbing

Reserve the permanent issuer, configure DNS/TLS/reverse proxy, provision Postgres and SMTP credentials, define backup and restore procedures, and freeze the OIDC/WebAuthn security contract before integrating a service.

### Phase 1 — Claustra in isolation

Implement public registration, multiple passkeys, SSO sessions, optional profile and verified email, consent, recovery quarantine, deletion, administration, audit retention, OIDC discovery, Authorization Code + PKCE, UserInfo, JWKS, and placeholder account/admin pages. Exercise the complete flow against a throwaway relying party.

### Phase 2 — First first-party integration

Integrate one low-risk server-backed web service using OIDC. Validate pairwise subjects, claim minimization, consent changes, client-secret rotation, logout boundaries, account deletion, and signing-key rotation.

### Phase 3 — Forward-auth adapter

Add the Caddy adapter using the same OIDC core. Test host-only cookies, strict return paths, direct-upstream isolation, XHR/API failures, revocation cascades, and break-glass behavior.

### Phase 4 — Service migration

Migrate Pagina, Euripus, Dashboard, and Lyra. Prefer native OIDC where the service can create its own local session; use forward-auth only when modifying the service is impractical. Remove replaced passwords and independent WebAuthn implementations rather than leaving silent alternate login paths.

### Phase 5 — Later clients

Consider Matrix integration, browser-only and native public clients, CLI/device authorization, refresh tokens, API-specific scopes and audiences, coordinated back-channel logout, and stronger authorization-server features only when a real consumer requires them.

## 16. Acceptance criteria for the first release

The first release is ready when:

- a new user can register with a passkey and no personal profile data;
- a user can add, verify, change, and remove optional profile information;
- two clients receive different stable `sub` values for the same user;
- a client receives no profile or email claim without the correct grant;
- a confidential web client completes Authorization Code + PKCE using discovery;
- replayed codes, mismatched redirect URIs, missing PKCE, wrong nonce, and stale challenges fail closed;
- email recovery observes the 24-hour quarantine and revokes older passkeys on completion;
- session, consent, credential, client, administrator, and account revocation behave as documented;
- deletion is reversible for seven days and permanent afterward;
- forward-auth does not expose the central SSO cookie to protected subdomains;
- a seven-generation encrypted backup can be restored using the documented procedure;
- security-sensitive logs contain no reusable credentials or personal profile values beyond the retention policy.

---

Claustra design v2 · protocol and behavior first, interface later.
