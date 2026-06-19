package store

import (
	"context"
	"fmt"
)

// GetAppSettings returns all stored application settings as a key/value map.
func (s *Store) GetAppSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Query(ctx, "SELECT key, value FROM app_settings")
	if err != nil {
		return nil, fmt.Errorf("get app settings: %w", err)
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scan app setting: %w", err)
		}
		settings[key] = value
	}
	return settings, rows.Err()
}

// SetAppSettings upserts the given key/value settings in a single transaction so
// a partial write never leaves an inconsistent policy.
func (s *Store) SetAppSettings(ctx context.Context, values map[string]string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin set app settings: %w", err)
	}
	defer tx.Rollback(ctx)

	for key, value := range values {
		if _, err := tx.Exec(ctx, `
INSERT INTO app_settings (key, value, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, value); err != nil {
			return fmt.Errorf("set app setting %q: %w", key, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit set app settings: %w", err)
	}
	return nil
}
