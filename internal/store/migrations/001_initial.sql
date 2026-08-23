CREATE TABLE users (
    id uuid PRIMARY KEY,
    webauthn_handle bytea NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deletion_pending')),
    display_name text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deletion_due_at timestamptz
);

CREATE TABLE user_emails (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email text NOT NULL,
    normalized_email text NOT NULL UNIQUE,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    credential jsonb NOT NULL,
    name text NOT NULL DEFAULT 'Passkey',
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'recovery_pending', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX credentials_user_id_idx ON credentials(user_id);

CREATE TABLE avatars (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    media_type text NOT NULL,
    image bytea NOT NULL,
    version uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sso_sessions (
    id_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id uuid REFERENCES credentials(id) ON DELETE SET NULL,
    auth_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    ip inet,
    user_agent text,
    revoked_at timestamptz
);
CREATE INDEX sso_sessions_user_id_idx ON sso_sessions(user_id);

CREATE TABLE webauthn_challenges (
    challenge_hash bytea PRIMARY KEY,
    operation text NOT NULL CHECK (operation IN ('register', 'login', 'reauth', 'add_passkey', 'recovery', 'delete_cancel')),
    transaction_id text NOT NULL,
    user_id uuid,
    user_webauthn_handle bytea,
    session_data jsonb NOT NULL,
    continuation jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX webauthn_challenges_transaction_idx ON webauthn_challenges(transaction_id);

CREATE TABLE clients (
    id text PRIMARY KEY,
    name text NOT NULL,
    logo_uri text,
    homepage_uri text,
    privacy_policy_uri text,
    trusted boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE client_redirect_uris (
    client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE client_secrets (
    id uuid PRIMARY KEY,
    client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    secret_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX client_secrets_client_idx ON client_secrets(client_id);

CREATE TABLE client_scopes (
    client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope text NOT NULL CHECK (scope IN ('openid', 'profile', 'email')),
    preapproved boolean NOT NULL DEFAULT false,
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE pairwise_subjects (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    subject text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE subject_tombstones (
    subject text PRIMARY KEY,
    deleted_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE consents (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes text[] NOT NULL,
    policy_version bigint NOT NULL DEFAULT 1,
    granted_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE authorization_codes (
    code_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    pkce_challenge text NOT NULL,
    nonce text NOT NULL,
    scopes text[] NOT NULL,
    auth_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE TABLE access_tokens (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    session_hash bytea REFERENCES sso_sessions(id_hash) ON DELETE SET NULL,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX access_tokens_user_idx ON access_tokens(user_id);

CREATE TABLE email_tokens (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('verify', 'recovery', 'delete_cancel')),
    pending_email text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE TABLE recoveries (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    replacement_credential_id uuid REFERENCES credentials(id) ON DELETE CASCADE,
    state text NOT NULL CHECK (state IN ('link_sent', 'quarantine', 'cancelled', 'completed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    completes_at timestamptz,
    completed_at timestamptz
);

CREATE TABLE forward_hosts (
    host text PRIMARY KEY,
    name text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE forward_subjects (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rp_host text NOT NULL REFERENCES forward_hosts(host) ON DELETE CASCADE,
    subject text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, rp_host)
);

CREATE TABLE forward_sessions (
    id_hash bytea PRIMARY KEY,
    sso_session_hash bytea NOT NULL REFERENCES sso_sessions(id_hash) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rp_host text NOT NULL REFERENCES forward_hosts(host) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX forward_sessions_user_idx ON forward_sessions(user_id);

CREATE TABLE forward_tickets (
    ticket_hash bytea PRIMARY KEY,
    sso_session_hash bytea NOT NULL REFERENCES sso_sessions(id_hash) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rp_host text NOT NULL REFERENCES forward_hosts(host) ON DELETE CASCADE,
    return_path text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE TABLE roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('admin')),
    granted_by uuid REFERENCES users(id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role)
);

CREATE TABLE bootstrap_tokens (
    token_hash bytea PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE TABLE audit_events (
    id bigserial PRIMARY KEY,
    timestamp timestamptz NOT NULL DEFAULT now(),
    event text NOT NULL,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    subject_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    client_id text REFERENCES clients(id) ON DELETE SET NULL,
    ip inet,
    user_agent text,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_timestamp_idx ON audit_events(timestamp);
CREATE INDEX audit_events_actor_idx ON audit_events(actor_user_id);
