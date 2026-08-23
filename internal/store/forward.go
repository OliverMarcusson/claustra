package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type ForwardHost struct {
	Host    string
	Name    string
	Enabled bool
}
type ForwardSession struct {
	Hash, SSOSessionHash []byte
	UserID               uuid.UUID
	Host                 string
	ExpiresAt            time.Time
}
type ForwardTicket struct {
	Hash, SSOSessionHash []byte
	UserID               uuid.UUID
	Host, ReturnPath     string
	ExpiresAt            time.Time
}

func (s *Store) ForwardHost(ctx context.Context, host string) (ForwardHost, error) {
	var v ForwardHost
	err := s.Pool.QueryRow(ctx, `SELECT host,name,enabled FROM forward_hosts WHERE host=$1`, host).Scan(&v.Host, &v.Name, &v.Enabled)
	return v, err
}
func (s *Store) ListForwardHosts(ctx context.Context) ([]ForwardHost, error) {
	rows, err := s.Pool.Query(ctx, `SELECT host,name,enabled FROM forward_hosts ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ForwardHost
	for rows.Next() {
		var v ForwardHost
		if err := rows.Scan(&v.Host, &v.Name, &v.Enabled); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) CreateForwardHost(ctx context.Context, host, name string, createdBy uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO forward_hosts(host,name,created_by) VALUES($1,$2,$3)`, host, name, createdBy)
	return err
}

func (s *Store) PutForwardTicket(ctx context.Context, t ForwardTicket) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO forward_tickets(ticket_hash,sso_session_hash,user_id,rp_host,return_path,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, t.Hash, t.SSOSessionHash, t.UserID, t.Host, t.ReturnPath, t.ExpiresAt)
	return err
}
func (s *Store) ConsumeForwardTicket(ctx context.Context, hash []byte, host string) (ForwardTicket, error) {
	var t ForwardTicket
	err := s.Pool.QueryRow(ctx, `UPDATE forward_tickets SET used_at=now() WHERE ticket_hash=$1 AND rp_host=$2 AND used_at IS NULL AND expires_at>now() RETURNING ticket_hash,sso_session_hash,user_id,rp_host,return_path,expires_at`, hash, host).Scan(&t.Hash, &t.SSOSessionHash, &t.UserID, &t.Host, &t.ReturnPath, &t.ExpiresAt)
	return t, err
}
func (s *Store) PutForwardSession(ctx context.Context, v ForwardSession) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO forward_sessions(id_hash,sso_session_hash,user_id,rp_host,expires_at) VALUES($1,$2,$3,$4,$5)`, v.Hash, v.SSOSessionHash, v.UserID, v.Host, v.ExpiresAt)
	return err
}
func (s *Store) ForwardSessionByRaw(ctx context.Context, raw, host string) (ForwardSession, error) {
	var v ForwardSession
	err := s.Pool.QueryRow(ctx, `SELECT f.id_hash,f.sso_session_hash,f.user_id,f.rp_host,f.expires_at FROM forward_sessions f JOIN sso_sessions s ON s.id_hash=f.sso_session_hash JOIN users u ON u.id=f.user_id WHERE f.id_hash=$1 AND f.rp_host=$2 AND f.revoked_at IS NULL AND f.expires_at>now() AND s.revoked_at IS NULL AND s.idle_expires_at>now() AND s.absolute_expires_at>now() AND u.status='active'`, HashSecret(raw), host).Scan(&v.Hash, &v.SSOSessionHash, &v.UserID, &v.Host, &v.ExpiresAt)
	return v, err
}
func (s *Store) RevokeForwardSession(ctx context.Context, hash []byte) error {
	_, err := s.Pool.Exec(ctx, `UPDATE forward_sessions SET revoked_at=now() WHERE id_hash=$1`, hash)
	return err
}
func (s *Store) ForwardSubject(ctx context.Context, userID uuid.UUID, host string) (string, error) {
	var subject string
	err := s.Pool.QueryRow(ctx, `SELECT subject FROM forward_subjects WHERE user_id=$1 AND rp_host=$2`, userID, host).Scan(&subject)
	if err == nil {
		return subject, nil
	}
	if !IsNotFound(err) {
		return "", err
	}
	subject = uuid.NewString()
	err = s.Pool.QueryRow(ctx, `INSERT INTO forward_subjects(user_id,rp_host,subject) VALUES($1,$2,$3) ON CONFLICT(user_id,rp_host) DO UPDATE SET user_id=excluded.user_id RETURNING subject`, userID, host, subject).Scan(&subject)
	return subject, err
}
