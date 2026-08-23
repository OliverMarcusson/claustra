-- Per-service access control.
--
-- Registration is public, so "has a Claustra account" was never meant to imply
-- "may use this service". A client or forward-auth host now carries a policy:
-- 'open' admits any active account, 'allowlist' admits only accounts holding a
-- verified email listed against that service.
--
-- New rows default to 'allowlist' with an empty list, so a service registered
-- and then forgotten admits nobody. Rows that already exist are moved to 'open'
-- to preserve the behaviour they were deployed with; tighten them by hand.

ALTER TABLE clients
    ADD COLUMN access_policy text NOT NULL DEFAULT 'allowlist'
    CHECK (access_policy IN ('open', 'allowlist'));

ALTER TABLE forward_hosts
    ADD COLUMN access_policy text NOT NULL DEFAULT 'allowlist'
    CHECK (access_policy IN ('open', 'allowlist'));

UPDATE clients SET access_policy = 'open';
UPDATE forward_hosts SET access_policy = 'open';

-- The listed value is the normalized form written by the server's
-- normalizeEmail, which is what user_emails.normalized_email holds. Joining on
-- anything else would make the match depend on how the address was typed.
CREATE TABLE client_allowed_emails (
    client_id text NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    normalized_email text NOT NULL,
    added_by uuid REFERENCES users(id) ON DELETE SET NULL,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, normalized_email)
);

CREATE TABLE forward_allowed_emails (
    rp_host text NOT NULL REFERENCES forward_hosts(host) ON DELETE CASCADE,
    normalized_email text NOT NULL,
    added_by uuid REFERENCES users(id) ON DELETE SET NULL,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rp_host, normalized_email)
);

-- Both allowlists are read on the authorization path and, for forward-auth, on
-- every proxied request. The lookup goes from a user's verified address to the
-- services it opens, so index the address rather than relying on the
-- service-first primary key.
CREATE INDEX client_allowed_emails_email_idx ON client_allowed_emails(normalized_email);
CREATE INDEX forward_allowed_emails_email_idx ON forward_allowed_emails(normalized_email);
