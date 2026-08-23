package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

func (s *Store) ScheduleDeletion(ctx context.Context, userID uuid.UUID, due time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE users SET status='deletion_pending',deletion_due_at=$2,updated_at=now() WHERE id=$1 AND status='active'`, userID, due); err != nil {
		return err
	}
	if err = revokeUserSessions(ctx, tx, userID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE consents SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CancelDeletion(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET status='active',deletion_due_at=NULL,updated_at=now() WHERE id=$1 AND status='deletion_pending' AND deletion_due_at>now()`, userID)
	return err
}

func (s *Store) DiscoverableDeletionUser(ctx context.Context, credentialID, userHandle []byte) (WebAuthnUser, error) {
	var userID uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT u.id FROM users u JOIN credentials c ON c.user_id=u.id WHERE c.credential_id=$1 AND u.webauthn_handle=$2 AND c.state='active' AND u.status='deletion_pending' AND u.deletion_due_at>now()`, credentialID, userHandle).Scan(&userID)
	if err != nil {
		return WebAuthnUser{}, err
	}
	return s.UserByID(ctx, userID)
}

func (s *Store) FinalizeDeletions(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM users WHERE status='deletion_pending' AND deletion_due_at<=now() FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO subject_tombstones(subject) SELECT subject FROM pairwise_subjects WHERE user_id=$1 ON CONFLICT DO NOTHING`, id); err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM users WHERE id=$1 AND status='deletion_pending' AND deletion_due_at<=now()`, id)
		}
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
