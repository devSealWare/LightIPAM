package store

import (
	"context"
	"fmt"

	"github.com/devSealWare/LightIPAM/internal/auth"
	"github.com/jackc/pgx/v5"
)

// FindUserByOIDCSubject resolves the local user bound to an IdP subject,
// ErrNotFound when none is linked yet.
func (s *Store) FindUserByOIDCSubject(ctx context.Context, subject string) (User, error) {
	var u User
	if err := s.db.QueryRow(ctx, `
SELECT id, username, display_name, password_hash, role, is_admin
FROM users WHERE oidc_subject = $1`, subject).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.IsAdmin); err != nil {
		if err == pgx.ErrNoRows {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("find user by oidc subject: %w", err)
	}
	return u, nil
}

// LinkOIDCSubject binds an IdP subject to an existing local user.
func (s *Store) LinkOIDCSubject(ctx context.Context, userID, subject string) error {
	if _, err := s.db.Exec(ctx, `UPDATE users SET oidc_subject = $2, updated_at = now() WHERE id = $1`, userID, subject); err != nil {
		return fmt.Errorf("link oidc subject: %w", err)
	}
	return nil
}

// CreateSSOUser provisions a local user for an SSO identity. It has no usable
// password (a random hash is stored so password login can never match) and is
// bound to the IdP subject.
func (s *Store) CreateSSOUser(ctx context.Context, username, displayName, role, subject string) (User, error) {
	id, err := auth.RandomToken(18)
	if err != nil {
		return User{}, err
	}
	randomPw, err := auth.RandomToken(32)
	if err != nil {
		return User{}, err
	}
	hash, err := auth.HashPassword(randomPw)
	if err != nil {
		return User{}, err
	}
	if !ValidRole(role) {
		role = RoleViewer
	}
	u := User{ID: id, Username: username, DisplayName: displayName, Role: role, IsAdmin: role == RoleAdmin}
	if err := s.db.QueryRow(ctx, `
INSERT INTO users (id, username, display_name, password_hash, role, is_admin, oidc_subject)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, username, display_name, role, is_admin`,
		u.ID, u.Username, u.DisplayName, hash, u.Role, u.IsAdmin, subject,
	).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.IsAdmin); err != nil {
		return User{}, fmt.Errorf("create sso user: %w", err)
	}
	return u, nil
}
