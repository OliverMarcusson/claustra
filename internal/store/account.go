package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var ErrLastCredential = errors.New("cannot revoke the final passkey")

type ConsentView struct {
	ClientID, ClientName string
	Scopes               []string
	GrantedAt            time.Time
}

func (s *Store) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id_hash,user_id,credential_id,auth_time,created_at,last_seen_at,idle_expires_at,absolute_expires_at,COALESCE(host(ip),''),user_agent FROM sso_sessions WHERE user_id=$1 AND revoked_at IS NULL AND idle_expires_at>now() AND absolute_expires_at>now() ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var v Session
		if err := rows.Scan(&v.Hash, &v.UserID, &v.CredentialID, &v.AuthTime, &v.CreatedAt, &v.LastSeenAt, &v.IdleExpiresAt, &v.AbsoluteExpiresAt, &v.IP, &v.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) RevokeOwnedSession(ctx context.Context, userID uuid.UUID, hash []byte) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=now() WHERE id_hash=$1 AND user_id=$2; UPDATE access_tokens SET revoked_at=now() WHERE session_hash=$1 AND user_id=$2`, hash, userID)
	return err
}

func (s *Store) RevokeCredential(ctx context.Context, userID, credentialID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var active int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE user_id=$1 AND state='active'`, userID).Scan(&active); err != nil {
		return err
	}
	if active <= 1 {
		return ErrLastCredential
	}
	tag, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked',revoked_at=now() WHERE id=$1 AND user_id=$2 AND state='active'`, credentialID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE sso_sessions SET revoked_at=now() WHERE user_id=$1 AND credential_id=$2 AND revoked_at IS NULL`, userID, credentialID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListConsents(ctx context.Context, userID uuid.UUID) ([]ConsentView, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.client_id,cl.name,c.scopes,c.granted_at FROM consents c JOIN clients cl ON cl.id=c.client_id WHERE c.user_id=$1 AND c.revoked_at IS NULL ORDER BY cl.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConsentView
	for rows.Next() {
		var v ConsentView
		if err := rows.Scan(&v.ClientID, &v.ClientName, &v.Scopes, &v.GrantedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) RevokeConsent(ctx context.Context, userID uuid.UUID, clientID string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE consents SET revoked_at=now(),updated_at=now() WHERE user_id=$1 AND client_id=$2`, userID, clientID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE access_tokens SET revoked_at=now() WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NULL`, userID, clientID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
