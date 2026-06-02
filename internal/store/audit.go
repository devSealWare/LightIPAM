package store

import (
	"context"
	"fmt"
	"time"
)

type AuditLog struct {
	ID               int64
	ActorUserID      string
	ActorDisplayName string
	Action           string
	SubjectType      string
	SubjectID        string
	Metadata         string
	CreatedAt        time.Time
}

type AuditFilters struct {
	Action      string
	SubjectType string
	ActorUserID string
	Limit       int
}

func (s *Store) ListAuditLogs(ctx context.Context, filters AuditFilters) ([]AuditLog, error) {
	limit := filters.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	rows, err := s.db.Query(ctx, `
SELECT a.id, COALESCE(a.actor_user_id, ''), COALESCE(u.display_name, ''), a.action, a.subject_type, COALESCE(a.subject_id, ''), a.metadata::text, a.created_at
FROM audit_logs a
LEFT JOIN users u ON u.id = a.actor_user_id
WHERE ($1 = '' OR a.action = $1)
AND ($2 = '' OR a.subject_type = $2)
AND ($3 = '' OR a.actor_user_id = $3)
ORDER BY a.created_at DESC
LIMIT $4`, filters.Action, filters.SubjectType, filters.ActorUserID, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var log AuditLog
		if err := rows.Scan(&log.ID, &log.ActorUserID, &log.ActorDisplayName, &log.Action, &log.SubjectType, &log.SubjectID, &log.Metadata, &log.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

func (s *Store) AuditActions(ctx context.Context) ([]string, error) {
	return s.distinctAuditValues(ctx, "action")
}

func (s *Store) AuditSubjectTypes(ctx context.Context) ([]string, error) {
	return s.distinctAuditValues(ctx, "subject_type")
}

func (s *Store) AuditActors(ctx context.Context) ([]User, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT u.id, u.username, u.display_name, u.password_hash, u.is_admin
FROM audit_logs a
JOIN users u ON u.id = a.actor_user_id
ORDER BY u.display_name`)
	if err != nil {
		return nil, fmt.Errorf("list audit actors: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.IsAdmin); err != nil {
			return nil, fmt.Errorf("scan audit actor: %w", err)
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) distinctAuditValues(ctx context.Context, column string) ([]string, error) {
	query := "SELECT DISTINCT " + column + " FROM audit_logs ORDER BY " + column
	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list audit %s values: %w", column, err)
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan audit value: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}
