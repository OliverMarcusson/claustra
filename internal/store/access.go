package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Access policies a client or forward-auth host can carry.
const (
	AccessOpen      = "open"
	AccessAllowlist = "allowlist"
)

func ValidAccessPolicy(value string) bool {
	return value == AccessOpen || value == AccessAllowlist
}

// NormalizeAccessPolicy resolves what a caller asked for into a policy the
// column will accept. An unset policy becomes 'allowlist': "the caller did not
// say" has to resolve to the closed answer, or forgetting the field anywhere in
// the codebase silently publishes a service.
func NormalizeAccessPolicy(value string) (string, error) {
	if value == "" {
		return AccessAllowlist, nil
	}
	if !ValidAccessPolicy(value) {
		return "", ErrInvalidPolicy
	}
	return value, nil
}

// allowedEmailPredicate is the SQL half of an access decision, shared so the
// OIDC path and the forward-auth path cannot drift apart. It reads a policy
// column and an allowlist table and yields true when the user may enter.
//
// Only a verified address counts. An unverified one is self-asserted, and
// treating it as proof would let anyone reach a gated service by claiming an
// address they do not control.
func allowedEmailPredicate(policyExpr, table, keyColumn, keyExpr, userExpr string) string {
	return `(` + policyExpr + ` = 'open' OR EXISTS (
		SELECT 1 FROM ` + table + ` a
		JOIN user_emails e ON e.normalized_email = a.normalized_email
		WHERE a.` + keyColumn + ` = ` + keyExpr + `
		  AND e.user_id = ` + userExpr + `
		  AND e.verified_at IS NOT NULL))`
}

var (
	clientAccessPredicate  = allowedEmailPredicate("c.access_policy", "client_allowed_emails", "client_id", "c.id", "$2")
	forwardAccessPredicate = allowedEmailPredicate("h.access_policy", "forward_allowed_emails", "rp_host", "h.host", "$2")
)

// ClientAccessAllowed reports whether the user may complete an authorization
// request for this client. A disabled or unknown client denies everyone.
func (s *Store) ClientAccessAllowed(ctx context.Context, clientID string, userID uuid.UUID) (bool, error) {
	var allowed bool
	err := s.Pool.QueryRow(ctx,
		`SELECT `+clientAccessPredicate+` FROM clients c WHERE c.id=$1 AND c.enabled`,
		clientID, userID).Scan(&allowed)
	if IsNotFound(err) {
		return false, nil
	}
	return allowed, err
}

// ForwardAccessAllowed reports whether the user may reach this forward-auth
// host. It is consulted when a ticket is issued and again on every proxied
// request, so removing an address takes effect without waiting for a session
// to expire.
func (s *Store) ForwardAccessAllowed(ctx context.Context, host string, userID uuid.UUID) (bool, error) {
	var allowed bool
	err := s.Pool.QueryRow(ctx,
		`SELECT `+forwardAccessPredicate+` FROM forward_hosts h WHERE h.host=$1 AND h.enabled`,
		host, userID).Scan(&allowed)
	if IsNotFound(err) {
		return false, nil
	}
	return allowed, err
}

func (s *Store) listAllowedEmails(ctx context.Context, query, key string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, query, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		out = append(out, email)
	}
	return out, rows.Err()
}

func (s *Store) ClientAllowedEmails(ctx context.Context, clientID string) ([]string, error) {
	return s.listAllowedEmails(ctx, `SELECT normalized_email FROM client_allowed_emails WHERE client_id=$1 ORDER BY normalized_email`, clientID)
}
func (s *Store) ForwardAllowedEmails(ctx context.Context, host string) ([]string, error) {
	return s.listAllowedEmails(ctx, `SELECT normalized_email FROM forward_allowed_emails WHERE rp_host=$1 ORDER BY normalized_email`, host)
}

func (s *Store) AllowClientEmail(ctx context.Context, clientID, normalized string, actor uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO client_allowed_emails(client_id,normalized_email,added_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, clientID, normalized, actor)
	return err
}
func (s *Store) AllowForwardEmail(ctx context.Context, host, normalized string, actor uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO forward_allowed_emails(rp_host,normalized_email,added_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, host, normalized, actor)
	return err
}

// DenyClientEmail removes an address and, in the same transaction, revokes the
// access tokens it is currently holding. Leaving them alive would keep UserInfo
// answering for up to their full lifetime after access was withdrawn.
func (s *Store) DenyClientEmail(ctx context.Context, clientID, normalized string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM client_allowed_emails WHERE client_id=$1 AND normalized_email=$2`, clientID, normalized); err != nil {
		return err
	}
	if err = revokeClientAccessForNewlyDenied(ctx, tx, clientID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DenyForwardEmail removes an address and drops the forward-auth sessions it is
// holding, so the next request re-runs the check instead of riding a cookie
// that was minted while the address was still listed.
func (s *Store) DenyForwardEmail(ctx context.Context, host, normalized string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM forward_allowed_emails WHERE rp_host=$1 AND normalized_email=$2`, host, normalized); err != nil {
		return err
	}
	if err = revokeForwardSessionsForNewlyDenied(ctx, tx, host); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetClientAccessPolicy switches a client between 'open' and 'allowlist',
// revoking whatever the change locks out.
func (s *Store) SetClientAccessPolicy(ctx context.Context, clientID, policy string) error {
	if !ValidAccessPolicy(policy) {
		return ErrInvalidPolicy
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE clients SET access_policy=$2,updated_at=now() WHERE id=$1`, clientID, policy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	if err = revokeClientAccessForNewlyDenied(ctx, tx, clientID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetForwardAccessPolicy(ctx context.Context, host, policy string) error {
	if !ValidAccessPolicy(policy) {
		return ErrInvalidPolicy
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE forward_hosts SET access_policy=$2 WHERE host=$1`, host, policy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	if err = revokeForwardSessionsForNewlyDenied(ctx, tx, host); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var ErrInvalidPolicy = errors.New("unknown access policy")

// Predicate variants that read the user from the row being revoked rather than
// from a parameter, for the bulk revocations below.
var (
	clientAccessForToken    = allowedEmailPredicate("c.access_policy", "client_allowed_emails", "client_id", "c.id", "t.user_id")
	forwardAccessForSession = allowedEmailPredicate("h.access_policy", "forward_allowed_emails", "rp_host", "h.host", "f.user_id")
)

// revokeClientAccessForNewlyDenied revokes every live access token held by a
// user the current policy no longer admits. Called after any change to a
// client's policy or allowlist, inside that change's transaction, so access
// never outlives the decision that granted it.
func revokeClientAccessForNewlyDenied(ctx context.Context, tx pgx.Tx, clientID string) error {
	_, err := tx.Exec(ctx, `UPDATE access_tokens t SET revoked_at=now()
		WHERE t.client_id=$1 AND t.revoked_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM clients c WHERE c.id=$1 AND c.enabled AND `+clientAccessForToken+`)`, clientID)
	return err
}

// revokeForwardSessionsForNewlyDenied does the same for forward-auth cookies.
// forwardVerify re-checks on every request anyway, so this is belt and braces —
// but it also makes the revocation visible in the user's session list rather
// than leaving a session that silently stopped working.
func revokeForwardSessionsForNewlyDenied(ctx context.Context, tx pgx.Tx, host string) error {
	_, err := tx.Exec(ctx, `UPDATE forward_sessions f SET revoked_at=now()
		WHERE f.rp_host=$1 AND f.revoked_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM forward_hosts h WHERE h.host=$1 AND h.enabled AND `+forwardAccessForSession+`)`, host)
	return err
}
