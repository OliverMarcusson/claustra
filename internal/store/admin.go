package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type AdminView struct {
	UserID      uuid.UUID
	DisplayName string
	Email       string
	GrantedAt   time.Time
}

func (s *Store) RotateClientSecret(ctx context.Context, clientID string, hash []byte) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	var enabled bool
	if err = tx.QueryRow(ctx, `SELECT enabled FROM clients WHERE id=$1 FOR UPDATE`, clientID).Scan(&enabled); err != nil {
		return uuid.Nil, err
	}
	if !enabled {
		return uuid.Nil, ErrNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE client_secrets SET expires_at=LEAST(COALESCE(expires_at,now()+interval '24 hours'),now()+interval '24 hours') WHERE client_id=$1 AND revoked_at IS NULL`, clientID); err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO client_secrets(id,client_id,secret_hash) VALUES($1,$2,$3)`, id, clientID, hash); err != nil {
		return uuid.Nil, err
	}
	return id, tx.Commit(ctx)
}
func (s *Store) SetClientEnabled(ctx context.Context, clientID string, enabled bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE clients SET enabled=$2,updated_at=now() WHERE id=$1`, clientID, enabled); err != nil {
		return err
	}
	if !enabled {
		if _, err = tx.Exec(ctx, `UPDATE access_tokens SET revoked_at=now() WHERE client_id=$1 AND revoked_at IS NULL`, clientID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) ListAdmins(ctx context.Context) ([]AdminView, error) {
	rows, err := s.Pool.Query(ctx, `SELECT u.id,COALESCE(u.display_name,''),COALESCE(e.email,''),r.granted_at FROM roles r JOIN users u ON u.id=r.user_id LEFT JOIN user_emails e ON e.user_id=u.id WHERE r.role='admin' ORDER BY r.granted_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminView
	for rows.Next() {
		var v AdminView
		if err := rows.Scan(&v.UserID, &v.DisplayName, &v.Email, &v.GrantedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) SetAdmin(ctx context.Context, actor, target uuid.UUID, enabled bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1129075506)`); err != nil {
		return err
	}
	if enabled {
		tag, err := tx.Exec(ctx, `INSERT INTO roles(user_id,role,granted_by) SELECT id,'admin',$2 FROM users WHERE id=$1 AND status='active' ON CONFLICT DO NOTHING`, target, actor)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
	} else {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM roles WHERE role='admin'`).Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			return errors.New("cannot remove the final administrator")
		}
		if _, err = tx.Exec(ctx, `DELETE FROM roles WHERE user_id=$1 AND role='admin'`, target); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
