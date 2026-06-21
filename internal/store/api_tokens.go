package store

import (
	"context"
	"fmt"
	"time"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
)

// APIToken is a per-user bearer credential for the machine API (Phase 6, ADR
// 0024). The hash is never exposed; the plaintext is shown once at creation.
type APIToken struct {
	ID         string
	UserID     string
	Name       string
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

// CreateAPIToken stores a new token's hash for a user and returns its metadata.
func (s *Store) CreateAPIToken(ctx context.Context, userID, name, tokenHash string) (APIToken, error) {
	id, err := auth.RandomToken(12)
	if err != nil {
		return APIToken{}, err
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO api_tokens (id, user_id, name, token_hash)
VALUES ($1, $2, $3, $4)`, id, userID, name, tokenHash); err != nil {
		return APIToken{}, fmt.Errorf("create api token: %w", err)
	}
	return s.GetAPIToken(ctx, id)
}

func (s *Store) GetAPIToken(ctx context.Context, id string) (APIToken, error) {
	var t APIToken
	if err := s.db.QueryRow(ctx, `
SELECT id, user_id, name, last_used_at, created_at FROM api_tokens WHERE id = $1`, id).Scan(
		&t.ID, &t.UserID, &t.Name, &t.LastUsedAt, &t.CreatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return APIToken{}, ErrNotFound
		}
		return APIToken{}, fmt.Errorf("get api token: %w", err)
	}
	return t, nil
}

// ListAPITokens returns a user's tokens, newest first.
func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, user_id, name, last_used_at, created_at
FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	var tokens []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// DeleteAPIToken revokes a token, scoped to its owner so a user can only delete
// their own.
func (s *Store) DeleteAPIToken(ctx context.Context, id, userID string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM api_tokens WHERE id = $1 AND user_id = $2", id, userID)
	if err != nil {
		return fmt.Errorf("delete api token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateAPIToken resolves a presented token hash to its owning user (with
// role), refreshing last_used_at. Returns ErrNotFound when no token matches.
func (s *Store) AuthenticateAPIToken(ctx context.Context, tokenHash string) (User, error) {
	var u User
	if err := s.db.QueryRow(ctx, `
WITH touched AS (
	UPDATE api_tokens SET last_used_at = now() WHERE token_hash = $1 RETURNING user_id
)
SELECT u.id, u.username, u.display_name, u.role, u.is_admin
FROM touched t JOIN users u ON u.id = t.user_id`, tokenHash).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.IsAdmin); err != nil {
		if err == pgx.ErrNoRows {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("authenticate api token: %w", err)
	}
	return u, nil
}
