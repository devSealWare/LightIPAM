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
	ID         string
	User       User
	CSRFToken  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	LastSeenAt time.Time
	ClientIP   string
	UserAgent  string
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

func (s *Store) CreateSession(ctx context.Context, userID string, expiresAt time.Time, clientIP, userAgent string) (Session, error) {
	id, err := auth.RandomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := auth.RandomToken(32)
	if err != nil {
		return Session{}, err
	}
	var session Session
	if err := s.db.QueryRow(ctx, `
INSERT INTO sessions (id, user_id, csrf_token, expires_at, client_ip, user_agent)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, csrf_token, expires_at, created_at, last_seen_at, client_ip, user_agent`,
		id, userID, csrf, expiresAt, clientIP, userAgent).Scan(
		&session.ID,
		&session.CSRFToken,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.LastSeenAt,
		&session.ClientIP,
		&session.UserAgent,
	); err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return session, nil
}

// GetSession loads a live session and refreshes its last_seen_at in one atomic
// statement. A session is live only when it has not passed its absolute expiry
// (expires_at) and has been touched since idleCutoff; both checks see the
// pre-update row, so the refresh slides the idle window forward on each request.
// A zero idleCutoff disables the idle check.
func (s *Store) GetSession(ctx context.Context, sessionID string, idleCutoff time.Time) (Session, error) {
	var session Session
	if err := s.db.QueryRow(ctx, `
WITH touched AS (
	UPDATE sessions
	SET last_seen_at = now()
	WHERE id = $1 AND expires_at > now() AND last_seen_at > $2
	RETURNING id, user_id, csrf_token, expires_at, created_at, last_seen_at, client_ip, user_agent
)
SELECT t.id, t.csrf_token, t.expires_at, t.created_at, t.last_seen_at, t.client_ip, t.user_agent,
       u.id, u.username, u.display_name, u.password_hash, u.is_admin
FROM touched t
JOIN users u ON u.id = t.user_id`, sessionID, idleCutoff).Scan(
		&session.ID,
		&session.CSRFToken,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.LastSeenAt,
		&session.ClientIP,
		&session.UserAgent,
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

// ListUserSessions returns a user's live sessions (not expired, touched since
// idleCutoff) most-recently-active first, for the account security page. A zero
// idleCutoff lists all unexpired sessions.
func (s *Store) ListUserSessions(ctx context.Context, userID string, idleCutoff time.Time) ([]Session, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, csrf_token, expires_at, created_at, last_seen_at, client_ip, user_agent
FROM sessions
WHERE user_id = $1 AND expires_at > now() AND last_seen_at > $2
ORDER BY last_seen_at DESC`, userID, idleCutoff)
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		if err := rows.Scan(
			&session.ID,
			&session.CSRFToken,
			&session.ExpiresAt,
			&session.CreatedAt,
			&session.LastSeenAt,
			&session.ClientIP,
			&session.UserAgent,
		); err != nil {
			return nil, fmt.Errorf("scan user session: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// DeleteUserSessions removes every session for a user ("log out everywhere"),
// returning how many were revoked.
func (s *Store) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)
	if err != nil {
		return 0, fmt.Errorf("delete user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteOtherUserSessions removes a user's sessions except the one given ("log
// out everywhere" while keeping the current device signed in), returning how
// many were revoked.
func (s *Store) DeleteOtherUserSessions(ctx context.Context, userID, exceptID string) (int64, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1 AND id <> $2", userID, exceptID)
	if err != nil {
		return 0, fmt.Errorf("delete other user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Ping verifies the database connection for the readiness probe.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

// MigrationVersion reports the highest applied schema migration, 0 when none
// have run, for the readiness probe.
func (s *Store) MigrationVersion(ctx context.Context) (int, error) {
	var version int
	if err := s.db.QueryRow(ctx, "SELECT COALESCE(max(version), 0) FROM schema_migrations").Scan(&version); err != nil {
		return 0, fmt.Errorf("migration version: %w", err)
	}
	return version, nil
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
