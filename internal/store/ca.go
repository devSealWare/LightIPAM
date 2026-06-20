package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GetAppCA returns the stored managed-CA certificate (PEM) and its sealed
// private key, ErrNotFound when no CA has been generated yet.
func (s *Store) GetAppCA(ctx context.Context) (certPEM, sealedKey string, err error) {
	if err := s.db.QueryRow(ctx, `SELECT cert_pem, key_sealed FROM app_ca WHERE id = 1`).Scan(&certPEM, &sealedKey); err != nil {
		if err == pgx.ErrNoRows {
			return "", "", ErrNotFound
		}
		return "", "", fmt.Errorf("get app ca: %w", err)
	}
	return certPEM, sealedKey, nil
}

// SaveAppCA stores (or replaces) the managed CA. The key must already be sealed.
func (s *Store) SaveAppCA(ctx context.Context, certPEM, sealedKey string) error {
	if _, err := s.db.Exec(ctx, `
INSERT INTO app_ca (id, cert_pem, key_sealed, created_at)
VALUES (1, $1, $2, now())
ON CONFLICT (id) DO UPDATE SET cert_pem = EXCLUDED.cert_pem, key_sealed = EXCLUDED.key_sealed, created_at = now()`,
		certPEM, sealedKey); err != nil {
		return fmt.Errorf("save app ca: %w", err)
	}
	return nil
}
