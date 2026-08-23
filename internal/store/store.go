package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var ErrNotFound = pgx.ErrNoRows

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() { s.Pool.Close() }

func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock(1129075505)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(1129075505)`)
	if _, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var applied bool
		err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, entry.Name()).Scan(&applied)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, string(sql)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES($1)`, entry.Name())
		}
		if err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", entry.Name(), err)
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func HashSecret(value string) []byte { sum := sha256.Sum256([]byte(value)); return sum[:] }
func HashBytes(value []byte) []byte  { sum := sha256.Sum256(value); return sum[:] }

type User struct {
	ID             uuid.UUID
	WebAuthnHandle []byte
	Status         string
	DisplayName    *string
	Email          *string
	EmailVerified  bool
	CreatedAt      time.Time
}

type Client struct {
	ID                string
	Name              string
	LogoURI           string
	HomepageURI       string
	PrivacyPolicyURI  string
	Trusted           bool
	Enabled           bool
	RedirectURIs      []string
	AllowedScopes     []string
	PreapprovedScopes []string
}

type Challenge struct {
	Hash          []byte
	Operation     string
	TransactionID string
	UserID        *uuid.UUID
	UserHandle    []byte
	SessionData   json.RawMessage
	Continuation  json.RawMessage
	ExpiresAt     time.Time
}

type Session struct {
	Hash              []byte
	UserID            uuid.UUID
	CredentialID      *uuid.UUID
	AuthTime          time.Time
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	IP                string
	UserAgent         string
}

func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
