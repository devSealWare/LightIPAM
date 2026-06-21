package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	db *pgxpool.Pool

	// auditHook, when set, is invoked after every successful audit-log insert. It
	// is the single fan-out point used to drive change webhooks (Phase 6, ADR
	// 0022) without instrumenting each handler. Guarded by auditMu because the
	// scheduler goroutine may write audit logs before the hook is registered at
	// startup. The hook must be cheap and non-blocking (the webhook dispatcher
	// hands off to a goroutine).
	auditMu   sync.RWMutex
	auditHook AuditHook
}

// AuditRecord is the immutable detail of an audit-log entry handed to an
// AuditHook.
type AuditRecord struct {
	ActorUserID *string
	Action      string
	SubjectType string
	SubjectID   string
	Metadata    string // JSON object
}

// AuditHook receives each audit entry after it is persisted.
type AuditHook func(ctx context.Context, rec AuditRecord)

// SetAuditHook registers (or clears, with nil) the audit fan-out hook. Safe to
// call concurrently with audit writes.
func (s *Store) SetAuditHook(hook AuditHook) {
	s.auditMu.Lock()
	s.auditHook = hook
	s.auditMu.Unlock()
}

// Roles. A user is either an admin (full read/write, manages users and
// settings) or a viewer (read-only operator). Role is the authoritative
// authorization field; IsAdmin is kept in sync for legacy queries.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// ValidRole reports whether role is one of the known roles.
func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleViewer
}

type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string
	Role         string
	IsAdmin      bool
	CreatedAt    time.Time
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
	user := User{ID: id, Username: username, DisplayName: displayName, PasswordHash: passwordHash, Role: RoleAdmin, IsAdmin: true}
	if err := s.db.QueryRow(ctx, `
INSERT INTO users (id, username, display_name, password_hash, role, is_admin)
VALUES ($1, $2, $3, $4, 'admin', true)
RETURNING id, username, display_name, password_hash, role, is_admin`,
		user.ID,
		user.Username,
		user.DisplayName,
		user.PasswordHash,
	).Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.Role, &user.IsAdmin); err != nil {
		return User{}, fmt.Errorf("create admin: %w", err)
	}
	return user, nil
}

// CreateUser adds a local user with the given role. An admin role sets is_admin
// for legacy queries; any other role is a read-only viewer.
func (s *Store) CreateUser(ctx context.Context, username, displayName, passwordHash, role string) (User, error) {
	id, err := auth.RandomToken(18)
	if err != nil {
		return User{}, err
	}
	if !ValidRole(role) {
		role = RoleViewer
	}
	user := User{ID: id, Username: username, DisplayName: displayName, PasswordHash: passwordHash, Role: role, IsAdmin: role == RoleAdmin}
	if err := s.db.QueryRow(ctx, `
INSERT INTO users (id, username, display_name, password_hash, role, is_admin)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, username, display_name, password_hash, role, is_admin`,
		user.ID, user.Username, user.DisplayName, user.PasswordHash, user.Role, user.IsAdmin,
	).Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.Role, &user.IsAdmin); err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

// ListUsers returns all accounts ordered by username for the Users settings tab.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, username, display_name, role, is_admin, created_at
FROM users
ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.IsAdmin, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// GetUser loads a single account by id.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	var u User
	if err := s.db.QueryRow(ctx, `
SELECT id, username, display_name, password_hash, role, is_admin, created_at
FROM users WHERE id = $1`, id).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.IsAdmin, &u.CreatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// SetUserRole changes a user's role, keeping is_admin in sync.
func (s *Store) SetUserRole(ctx context.Context, id, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	if _, err := s.db.Exec(ctx, `UPDATE users SET role = $2, is_admin = $3, updated_at = now() WHERE id = $1`,
		id, role, role == RoleAdmin); err != nil {
		return fmt.Errorf("set user role: %w", err)
	}
	return nil
}

// SetUserPassword updates a user's password hash (admin reset or self-service).
func (s *Store) SetUserPassword(ctx context.Context, id, passwordHash string) error {
	if _, err := s.db.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, passwordHash); err != nil {
		return fmt.Errorf("set user password: %w", err)
	}
	return nil
}

// DeleteUser removes a user account. Sessions cascade.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

func (s *Store) FindUserByUsername(ctx context.Context, username string) (User, error) {
	var user User
	if err := s.db.QueryRow(ctx, `
SELECT id, username, display_name, password_hash, role, is_admin
FROM users
WHERE username = $1`, username).Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.Role, &user.IsAdmin); err != nil {
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
       u.id, u.username, u.display_name, u.password_hash, u.role, u.is_admin
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
		&session.User.Role,
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
	s.auditMu.RLock()
	hook := s.auditHook
	s.auditMu.RUnlock()
	if hook != nil {
		hook(ctx, AuditRecord{
			ActorUserID: actorUserID,
			Action:      action,
			SubjectType: subjectType,
			SubjectID:   subjectID,
			Metadata:    metadata,
		})
	}
	return nil
}
