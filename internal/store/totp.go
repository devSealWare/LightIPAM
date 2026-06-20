package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// UserTOTP is a user's stored second-factor enrollment. Secret is sealed at
// rest by the caller (internal/secret); the store never sees plaintext.
type UserTOTP struct {
	UserID      string
	Secret      string
	Enabled     bool
	ConfirmedAt *time.Time
}

// GetUserTOTP loads a user's TOTP enrollment, ErrNotFound when none exists.
func (s *Store) GetUserTOTP(ctx context.Context, userID string) (UserTOTP, error) {
	var t UserTOTP
	if err := s.db.QueryRow(ctx, `
SELECT user_id, secret, enabled, confirmed_at
FROM user_totp WHERE user_id = $1`, userID).Scan(&t.UserID, &t.Secret, &t.Enabled, &t.ConfirmedAt); err != nil {
		if err == pgx.ErrNoRows {
			return UserTOTP{}, ErrNotFound
		}
		return UserTOTP{}, fmt.Errorf("get user totp: %w", err)
	}
	return t, nil
}

// TOTPEnabled reports whether a user has a confirmed second factor.
func (s *Store) TOTPEnabled(ctx context.Context, userID string) (bool, error) {
	var enabled bool
	err := s.db.QueryRow(ctx, `SELECT enabled FROM user_totp WHERE user_id = $1`, userID).Scan(&enabled)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("totp enabled: %w", err)
	}
	return enabled, nil
}

// StartTOTPEnrollment stores a fresh (sealed) pending secret, replacing any
// prior unconfirmed enrollment.
func (s *Store) StartTOTPEnrollment(ctx context.Context, userID, sealedSecret string) error {
	if _, err := s.db.Exec(ctx, `
INSERT INTO user_totp (user_id, secret, enabled, confirmed_at)
VALUES ($1, $2, false, NULL)
ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, enabled = false, confirmed_at = NULL, created_at = now()`,
		userID, sealedSecret); err != nil {
		return fmt.Errorf("start totp enrollment: %w", err)
	}
	return nil
}

// EnableTOTP confirms a pending enrollment and stores the recovery-code hashes
// in one transaction.
func (s *Store) EnableTOTP(ctx context.Context, userID string, recoveryHashes []string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin enable totp: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `UPDATE user_totp SET enabled = true, confirmed_at = now() WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("clear recovery codes: %w", err)
	}
	for _, h := range recoveryHashes {
		if _, err := tx.Exec(ctx, `INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// DisableTOTP removes a user's second factor and recovery codes.
func (s *Store) DisableTOTP(ctx context.Context, userID string) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM user_totp WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	return nil
}

// ConsumeRecoveryCode marks the first matching unused recovery code as used,
// returning true when a code was consumed.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE user_recovery_codes SET used_at = now()
WHERE id = (
	SELECT id FROM user_recovery_codes
	WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
	LIMIT 1
)`, userID, codeHash)
	if err != nil {
		return false, fmt.Errorf("consume recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// CountUnusedRecoveryCodes returns how many recovery codes remain.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID string) (int, error) {
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}
	return n, nil
}
