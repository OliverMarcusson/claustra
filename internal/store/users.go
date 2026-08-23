package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type Credential struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Data       webauthn.Credential
	Name       string
	State      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

type WebAuthnUser struct {
	User
	Credentials []Credential
}

func (u WebAuthnUser) WebAuthnID() []byte { return u.WebAuthnHandle }
func (u WebAuthnUser) WebAuthnName() string {
	if u.DisplayName != nil && *u.DisplayName != "" {
		return *u.DisplayName
	}
	if u.Email != nil && *u.Email != "" {
		return *u.Email
	}
	return "Claustra account"
}
func (u WebAuthnUser) WebAuthnDisplayName() string { return u.WebAuthnName() }
func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.Credentials))
	for _, credential := range u.Credentials {
		if credential.State == "active" {
			out = append(out, credential.Data)
		}
	}
	return out
}

func (s *Store) CreateUserWithCredential(ctx context.Context, user User, credential webauthn.Credential, credentialName string, bootstrapHash []byte) (uuid.UUID, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, false, err
	}
	defer tx.Rollback(ctx)
	admin := false
	if len(bootstrapHash) > 0 {
		var one int
		err = tx.QueryRow(ctx, `UPDATE bootstrap_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() AND NOT EXISTS(SELECT 1 FROM roles WHERE role='admin') RETURNING 1`, bootstrapHash).Scan(&one)
		if err != nil && !IsNotFound(err) {
			return uuid.Nil, false, err
		}
		admin = err == nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO users(id, webauthn_handle, status, display_name, created_at, updated_at) VALUES($1,$2,'active',$3,$4,$4)`, user.ID, user.WebAuthnHandle, user.DisplayName, user.CreatedAt)
	if err != nil {
		return uuid.Nil, false, err
	}
	credentialID := uuid.New()
	data, err := json.Marshal(credential)
	if err != nil {
		return uuid.Nil, false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO credentials(id,user_id,credential_id,credential,name,state) VALUES($1,$2,$3,$4,$5,'active')`, credentialID, user.ID, credential.ID, data, credentialName)
	if err != nil {
		return uuid.Nil, false, err
	}
	if admin {
		_, err = tx.Exec(ctx, `INSERT INTO roles(user_id,role,granted_by) VALUES($1,'admin',$1)`, user.ID)
		if err != nil {
			return uuid.Nil, false, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return uuid.Nil, false, err
	}
	return credentialID, admin, nil
}

func (s *Store) loadWebAuthnUser(ctx context.Context, column string, value any) (WebAuthnUser, error) {
	query := `SELECT u.id,u.webauthn_handle,u.status,u.display_name,e.email,e.verified_at,u.created_at
              FROM users u LEFT JOIN user_emails e ON e.user_id=u.id WHERE ` + column + `=$1`
	var u WebAuthnUser
	var verifiedAt *time.Time
	err := s.Pool.QueryRow(ctx, query, value).Scan(&u.ID, &u.WebAuthnHandle, &u.Status, &u.DisplayName, &u.Email, &verifiedAt, &u.CreatedAt)
	if err != nil {
		return WebAuthnUser{}, err
	}
	u.EmailVerified = verifiedAt != nil
	rows, err := s.Pool.Query(ctx, `SELECT id,user_id,credential,name,state,created_at,last_used_at FROM credentials WHERE user_id=$1 AND state IN ('active','recovery_pending') ORDER BY created_at`, u.ID)
	if err != nil {
		return WebAuthnUser{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Credential
		var data []byte
		if err := rows.Scan(&c.ID, &c.UserID, &data, &c.Name, &c.State, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return WebAuthnUser{}, err
		}
		if err := json.Unmarshal(data, &c.Data); err != nil {
			return WebAuthnUser{}, fmt.Errorf("decode credential: %w", err)
		}
		u.Credentials = append(u.Credentials, c)
	}
	return u, rows.Err()
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (WebAuthnUser, error) {
	return s.loadWebAuthnUser(ctx, "u.id", id)
}
func (s *Store) UserByHandle(ctx context.Context, handle []byte) (WebAuthnUser, error) {
	return s.loadWebAuthnUser(ctx, "u.webauthn_handle", handle)
}

// CredentialKnown reports whether this credential exists at all, ignoring which
// account it belongs to and what state it is in. It separates a passkey Claustra
// never stored - one left behind by a registration that failed after the
// browser had already created it - from a credential it holds but could not
// match to the asserted user handle.
func (s *Store) CredentialKnown(ctx context.Context, credentialID []byte) bool {
	var exists bool
	_ = s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM credentials WHERE credential_id=$1)`, credentialID).Scan(&exists)
	return exists
}

func (s *Store) DiscoverableUser(ctx context.Context, credentialID, userHandle []byte) (WebAuthnUser, error) {
	var userID uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT u.id FROM users u JOIN credentials c ON c.user_id=u.id WHERE c.credential_id=$1 AND u.webauthn_handle=$2 AND c.state='active' AND u.status='active'`, credentialID, userHandle).Scan(&userID)
	if err != nil {
		return WebAuthnUser{}, err
	}
	return s.UserByID(ctx, userID)
}

func (s *Store) PutBootstrapToken(ctx context.Context, hash []byte, expires time.Time) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO bootstrap_tokens(token_hash,expires_at) VALUES($1,$2)`, hash, expires)
	return err
}

func (s *Store) ConsumeBootstrapToken(ctx context.Context, hash []byte) (bool, error) {
	var one int
	err := s.Pool.QueryRow(ctx, `UPDATE bootstrap_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() AND NOT EXISTS(SELECT 1 FROM roles WHERE role='admin') RETURNING 1`, hash).Scan(&one)
	if IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) UpdateCredential(ctx context.Context, userID uuid.UUID, credential webauthn.Credential) (uuid.UUID, error) {
	data, err := json.Marshal(credential)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = s.Pool.QueryRow(ctx, `UPDATE credentials SET credential=$1,last_used_at=now() WHERE user_id=$2 AND credential_id=$3 AND state='active' RETURNING id`, data, userID, credential.ID).Scan(&id)
	return id, err
}

func (s *Store) AddCredential(ctx context.Context, userID uuid.UUID, credential webauthn.Credential, name, state string) (uuid.UUID, error) {
	data, err := json.Marshal(credential)
	if err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	_, err = s.Pool.Exec(ctx, `INSERT INTO credentials(id,user_id,credential_id,credential,name,state) VALUES($1,$2,$3,$4,$5,$6)`, id, userID, credential.ID, data, name, state)
	return id, err
}

func (s *Store) PutChallenge(ctx context.Context, c Challenge) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO webauthn_challenges(challenge_hash,operation,transaction_id,user_id,user_webauthn_handle,session_data,continuation,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.Hash, c.Operation, c.TransactionID, c.UserID, c.UserHandle, c.SessionData, c.Continuation, c.ExpiresAt)
	return err
}

func (s *Store) ConsumeChallenge(ctx context.Context, hash []byte, operation string) (Challenge, error) {
	var c Challenge
	err := s.Pool.QueryRow(ctx, `UPDATE webauthn_challenges SET used_at=now() WHERE challenge_hash=$1 AND operation=$2 AND used_at IS NULL AND expires_at>now() RETURNING challenge_hash,operation,transaction_id,user_id,user_webauthn_handle,session_data,continuation,expires_at`, hash, operation).Scan(&c.Hash, &c.Operation, &c.TransactionID, &c.UserID, &c.UserHandle, &c.SessionData, &c.Continuation, &c.ExpiresAt)
	return c, err
}

func (s *Store) CreateSession(ctx context.Context, session Session) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO sso_sessions(id_hash,user_id,credential_id,auth_time,created_at,last_seen_at,idle_expires_at,absolute_expires_at,ip,user_agent) VALUES($1,$2,$3,$4,$5,$5,$6,$7,NULLIF($8,'')::inet,$9)`, session.Hash, session.UserID, session.CredentialID, session.AuthTime, session.CreatedAt, session.IdleExpiresAt, session.AbsoluteExpiresAt, session.IP, session.UserAgent)
	return err
}

func (s *Store) SessionByToken(ctx context.Context, token string, idleTTL time.Duration) (Session, error) {
	hash := HashSecret(token)
	var session Session
	err := s.Pool.QueryRow(ctx, `UPDATE sso_sessions s SET last_seen_at=now(),idle_expires_at=LEAST(now()+make_interval(secs=>$2),absolute_expires_at)
        FROM users u WHERE s.id_hash=$1 AND u.id=s.user_id AND u.status='active' AND s.revoked_at IS NULL AND s.idle_expires_at>now() AND s.absolute_expires_at>now()
        RETURNING s.id_hash,s.user_id,s.credential_id,s.auth_time,s.created_at,s.last_seen_at,s.idle_expires_at,s.absolute_expires_at,COALESCE(host(s.ip),''),s.user_agent`, hash, int64(idleTTL.Seconds())).Scan(&session.Hash, &session.UserID, &session.CredentialID, &session.AuthTime, &session.CreatedAt, &session.LastSeenAt, &session.IdleExpiresAt, &session.AbsoluteExpiresAt, &session.IP, &session.UserAgent)
	return session, err
}

func (s *Store) RevokeSession(ctx context.Context, hash []byte) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=now() WHERE id_hash=$1; UPDATE access_tokens SET revoked_at=now() WHERE session_hash=$1 AND revoked_at IS NULL`, hash)
	return err
}

func (s *Store) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL; UPDATE access_tokens SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return err
}

func (s *Store) IsAdmin(ctx context.Context, userID uuid.UUID) bool {
	var yes bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE user_id=$1 AND role='admin')`, userID).Scan(&yes); err != nil {
		return false
	}
	return yes
}

func (s *Store) HasAdmin(ctx context.Context) (bool, error) {
	var yes bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE role='admin')`).Scan(&yes)
	return yes, err
}

func (s *Store) IsLastAdmin(ctx context.Context, userID uuid.UUID) bool {
	var yes bool
	_ = s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE user_id=$1 AND role='admin') AND (SELECT count(*) FROM roles WHERE role='admin')=1`, userID).Scan(&yes)
	return yes
}

func (s *Store) Audit(ctx context.Context, event string, actor, subject *uuid.UUID, clientID *string, ip, ua string, detail any) {
	data, _ := json.Marshal(detail)
	_, _ = s.Pool.Exec(ctx, `INSERT INTO audit_events(event,actor_user_id,subject_user_id,client_id,ip,user_agent,detail) VALUES($1,$2,$3,$4,NULLIF($5,'')::inet,$6,$7)`, event, actor, subject, clientID, ip, ua, data)
}

func (s *Store) Cleanup(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `
        DELETE FROM webauthn_challenges WHERE expires_at < now()-interval '1 hour';
        DELETE FROM authorization_codes WHERE expires_at < now()-interval '1 hour';
        DELETE FROM access_tokens WHERE expires_at < now()-interval '1 day';
        DELETE FROM email_tokens WHERE expires_at < now()-interval '1 day';
		DELETE FROM forward_tickets WHERE expires_at < now()-interval '1 hour';
		DELETE FROM forward_sessions WHERE expires_at < now()-interval '1 day' OR revoked_at < now()-interval '1 day';
		DELETE FROM sso_sessions WHERE idle_expires_at < now()-interval '1 day' OR absolute_expires_at < now()-interval '1 day' OR revoked_at < now()-interval '1 day';
        UPDATE audit_events SET ip=NULL,user_agent=NULL WHERE timestamp < now()-interval '30 days' AND (ip IS NOT NULL OR user_agent IS NOT NULL);
        DELETE FROM audit_events WHERE timestamp < now()-interval '1 year';`)
	return err
}

func (s *Store) InvalidateEphemeralState(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=now() WHERE revoked_at IS NULL; UPDATE access_tokens SET revoked_at=now() WHERE revoked_at IS NULL; DELETE FROM authorization_codes; DELETE FROM webauthn_challenges; DELETE FROM email_tokens; DELETE FROM forward_tickets; UPDATE forward_sessions SET revoked_at=now() WHERE revoked_at IS NULL; UPDATE credentials SET state='revoked',revoked_at=now() WHERE state='recovery_pending'; UPDATE recoveries SET state='cancelled',completed_at=now() WHERE state IN ('link_sent','quarantine')`)
	return err
}
