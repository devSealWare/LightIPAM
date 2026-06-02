package store

import (
	"context"
	"fmt"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	db *pgxpool.Pool
}

type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string
	IsAdmin      bool
}

type Session struct {
	ID        string
	User      User
	CSRFToken string
	ExpiresAt time.Time
}

func New(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM users WHERE is_admin").Scan(&count); err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return count, nil
}

func (s *Store) CreateAdmin(ctx context.Context, username, displayName, passwordHash string) (User, error) {
	id, err := auth.RandomToken(18)
	if err != nil {
		return User{}, err
	}
	user := User{ID: id, Username: username, DisplayName: displayName, PasswordHash: passwordHash, IsAdmin: true}
	if err := s.db.QueryRow(ctx, `
INSERT INTO users (id, username, display_name, password_hash, is_admin)
VALUES ($1, $2, $3, $4, true)
RETURNING id, username, display_name, password_hash, is_admin`,
		user.ID,
		user.Username,
		user.DisplayName,
		user.PasswordHash,
	).Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.IsAdmin); err != nil {
		return User{}, fmt.Errorf("create admin: %w", err)
	}
	return user, nil
}

func (s *Store) FindUserByUsername(ctx context.Context, username string) (User, error) {
	var user User
	if err := s.db.QueryRow(ctx, `
SELECT id, username, display_name, password_hash, is_admin
FROM users
WHERE username = $1`, username).Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.IsAdmin); err != nil {
		if err == pgx.ErrNoRows {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("find user by username: %w", err)
	}
	return user, nil
}

func (s *Store) CreateSession(ctx context.Context, userID string, expiresAt time.Time) (Session, error) {
	id, err := auth.RandomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := auth.RandomToken(32)
	if err != nil {
		return Session{}, err
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO sessions (id, user_id, csrf_token, expires_at)
VALUES ($1, $2, $3, $4)`, id, userID, csrf, expiresAt); err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return Session{ID: id, CSRFToken: csrf, ExpiresAt: expiresAt}, nil
}

func (s *Store) GetSession(ctx context.Context, sessionID string) (Session, error) {
	var session Session
	if err := s.db.QueryRow(ctx, `
SELECT s.id, s.csrf_token, s.expires_at, u.id, u.username, u.display_name, u.password_hash, u.is_admin
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.id = $1 AND s.expires_at > now()`, sessionID).Scan(
		&session.ID,
		&session.CSRFToken,
		&session.ExpiresAt,
		&session.User.ID,
		&session.User.Username,
		&session.User.DisplayName,
		&session.User.PasswordHash,
		&session.User.IsAdmin,
	); err != nil {
		if err == pgx.ErrNoRows {
			return Session{}, ErrNotFound
		}
		return Session{}, fmt.Errorf("get session: %w", err)
	}
	return session, nil
}

func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	if _, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE id = $1", sessionID); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Store) CreateAuditLog(ctx context.Context, actorUserID *string, action, subjectType, subjectID, metadata string) error {
	if metadata == "" {
		metadata = "{}"
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO audit_logs (actor_user_id, action, subject_type, subject_id, metadata)
VALUES ($1, $2, $3, $4, $5::jsonb)`, actorUserID, action, subjectType, subjectID, metadata); err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}
	return nil
}
