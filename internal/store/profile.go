package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

func (s *Store) UpdateDisplayName(ctx context.Context, userID uuid.UUID, name *string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET display_name=$2,updated_at=now() WHERE id=$1 AND status='active'`, userID, name)
	return err
}

func (s *Store) PutAvatar(ctx context.Context, userID uuid.UUID, mediaType string, image []byte) (uuid.UUID, error) {
	version := uuid.New()
	_, err := s.Pool.Exec(ctx, `INSERT INTO avatars(user_id,media_type,image,version) VALUES($1,$2,$3,$4) ON CONFLICT(user_id) DO UPDATE SET media_type=excluded.media_type,image=excluded.image,version=excluded.version,updated_at=now()`, userID, mediaType, image, version)
	return version, err
}
func (s *Store) Avatar(ctx context.Context, userID uuid.UUID) (string, []byte, uuid.UUID, error) {
	var mt string
	var image []byte
	var version uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT media_type,image,version FROM avatars WHERE user_id=$1`, userID).Scan(&mt, &image, &version)
	return mt, image, version, err
}
func (s *Store) HasAvatar(ctx context.Context, userID uuid.UUID) bool {
	var yes bool
	_ = s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM avatars WHERE user_id=$1)`, userID).Scan(&yes)
	return yes
}

func (s *Store) PutEmailToken(ctx context.Context, userID uuid.UUID, purpose, pendingEmail string, hash []byte, expires time.Time) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO email_tokens(token_hash,user_id,purpose,pending_email,expires_at) VALUES($1,$2,$3,NULLIF($4,''),$5)`, hash, userID, purpose, pendingEmail, expires)
	return err
}
func (s *Store) ConsumeEmailToken(ctx context.Context, hash []byte, purpose string) (uuid.UUID, string, error) {
	var userID uuid.UUID
	var pending string
	err := s.Pool.QueryRow(ctx, `UPDATE email_tokens SET used_at=now() WHERE token_hash=$1 AND purpose=$2 AND used_at IS NULL AND expires_at>now() RETURNING user_id,COALESCE(pending_email,'')`, hash, purpose).Scan(&userID, &pending)
	return userID, pending, err
}
func (s *Store) VerifyEmail(ctx context.Context, userID uuid.UUID, email, normalized string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO user_emails(user_id,email,normalized_email,verified_at) VALUES($1,$2,$3,now()) ON CONFLICT(user_id) DO UPDATE SET email=excluded.email,normalized_email=excluded.normalized_email,verified_at=now(),updated_at=now()`, userID, email, normalized)
	return err
}
func (s *Store) DeleteEmail(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM user_emails WHERE user_id=$1`, userID)
	return err
}
func (s *Store) UserByNormalizedEmail(ctx context.Context, email string) (User, error) {
	var u User
	var verified *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT u.id,u.webauthn_handle,u.status,u.display_name,e.email,e.verified_at,u.created_at FROM users u JOIN user_emails e ON e.user_id=u.id WHERE e.normalized_email=$1 AND e.verified_at IS NOT NULL`, email).Scan(&u.ID, &u.WebAuthnHandle, &u.Status, &u.DisplayName, &u.Email, &verified, &u.CreatedAt)
	u.EmailVerified = verified != nil
	return u, err
}

func (s *Store) RevokeTokenForClient(ctx context.Context, raw, clientID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE access_tokens SET revoked_at=now() WHERE token_hash=$1 AND client_id=$2`, HashSecret(raw), clientID)
	return err
}

func (s *Store) PeekEmailToken(ctx context.Context, hash []byte, purpose string) (uuid.UUID, string, error) {
	var userID uuid.UUID
	var pending string
	err := s.Pool.QueryRow(ctx, `SELECT user_id,COALESCE(pending_email,'') FROM email_tokens WHERE token_hash=$1 AND purpose=$2 AND used_at IS NULL AND expires_at>now()`, hash, purpose).Scan(&userID, &pending)
	return userID, pending, err
}
