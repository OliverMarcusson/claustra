package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func (s *Store) StartRecoveryRequest(ctx context.Context, userID uuid.UUID, tokenHash []byte, expires time.Time) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	var quarantine bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM recoveries WHERE user_id=$1 AND state='quarantine')`, userID).Scan(&quarantine); err != nil {
		return uuid.Nil, err
	}
	if quarantine {
		return uuid.Nil, errors.New("recovery already pending")
	}
	id := uuid.New()
	if _, err = tx.Exec(ctx, `UPDATE recoveries SET state='cancelled',completed_at=now() WHERE user_id=$1 AND state='link_sent'`, userID); err != nil {
		return uuid.Nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO recoveries(id,user_id,state) VALUES($1,$2,'link_sent')`, id, userID); err != nil {
		return uuid.Nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO email_tokens(token_hash,user_id,purpose,pending_email,expires_at) VALUES($1,$2,'recovery',$3,$4)`, tokenHash, userID, id.String(), expires); err != nil {
		return uuid.Nil, err
	}
	return id, tx.Commit(ctx)
}

func (s *Store) BeginRecoveryQuarantine(ctx context.Context, recoveryID, userID uuid.UUID, tokenHash []byte, credential webauthn.Credential, name string, delay time.Duration) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	var tokenUser uuid.UUID
	var pending string
	err = tx.QueryRow(ctx, `UPDATE email_tokens SET used_at=now() WHERE token_hash=$1 AND purpose='recovery' AND user_id=$2 AND pending_email=$3 AND used_at IS NULL AND expires_at>now() RETURNING user_id,COALESCE(pending_email,'')`, tokenHash, userID, recoveryID.String()).Scan(&tokenUser, &pending)
	if err != nil {
		return uuid.Nil, err
	}
	data, err := json.Marshal(credential)
	if err != nil {
		return uuid.Nil, err
	}
	credentialID := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO credentials(id,user_id,credential_id,credential,name,state) VALUES($1,$2,$3,$4,$5,'recovery_pending')`, credentialID, userID, credential.ID, data, name); err != nil {
		return uuid.Nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE recoveries SET replacement_credential_id=$1,state='quarantine',completes_at=now()+make_interval(secs=>$2) WHERE id=$3 AND user_id=$4 AND state='link_sent'`, credentialID, int64(delay.Seconds()), recoveryID, userID); err != nil {
		return uuid.Nil, err
	}
	return credentialID, tx.Commit(ctx)
}

func (s *Store) PendingRecovery(ctx context.Context, userID uuid.UUID) (uuid.UUID, time.Time, bool) {
	var id uuid.UUID
	var completes time.Time
	err := s.Pool.QueryRow(ctx, `SELECT id,completes_at FROM recoveries WHERE user_id=$1 AND state='quarantine' ORDER BY created_at DESC LIMIT 1`, userID).Scan(&id, &completes)
	return id, completes, err == nil
}

func (s *Store) CancelRecovery(ctx context.Context, userID, recoveryID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var replacement *uuid.UUID
	if err = tx.QueryRow(ctx, `UPDATE recoveries SET state='cancelled',completed_at=now() WHERE id=$1 AND user_id=$2 AND state IN ('link_sent','quarantine') RETURNING replacement_credential_id`, recoveryID, userID).Scan(&replacement); err != nil {
		return err
	}
	if replacement != nil {
		if _, err = tx.Exec(ctx, `UPDATE credentials SET state='revoked',revoked_at=now() WHERE id=$1`, *replacement); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) FinalizeRecoveries(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx, `SELECT id,user_id,replacement_credential_id FROM recoveries WHERE state='quarantine' AND completes_at<=now() FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return err
	}
	type item struct{ id, user, credential uuid.UUID }
	var items []item
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.id, &v.user, &v.credential); err != nil {
			rows.Close()
			return err
		}
		items = append(items, v)
	}
	rows.Close()
	for _, v := range items {
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE credentials SET state='revoked',revoked_at=now() WHERE user_id=$1 AND id<>$2 AND state<>'revoked'`, v.user, v.credential); err == nil {
			_, err = tx.Exec(ctx, `UPDATE credentials SET state='active' WHERE id=$1 AND user_id=$2 AND state='recovery_pending'`, v.credential, v.user)
		}
		if err == nil {
			err = revokeUserSessions(ctx, tx, v.user)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE recoveries SET state='completed',completed_at=now() WHERE id=$1 AND state='quarantine'`, v.id)
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
