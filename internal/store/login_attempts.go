package store

import (
	"context"
	"fmt"
	"time"
)

// LoginFailureStats summarizes recent failed login attempts within a window,
// counted separately for the attempted username and the client IP so the lock
// decision can throttle a targeted account and a noisy source independently.
type LoginFailureStats struct {
	UserFailures int
	UserLast     time.Time
	IPFailures   int
	IPLast       time.Time
}

// RecordLoginFailure stores one failed login attempt, keyed by both the
// attempted username and the client IP.
func (s *Store) RecordLoginFailure(ctx context.Context, username, ip string) error {
	if _, err := s.db.Exec(ctx,
		"INSERT INTO login_attempts (username, ip) VALUES ($1, $2)", username, ip); err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	return nil
}

// RecentLoginFailures counts failed attempts since the given time for the
// username and the IP, with the most recent timestamp for each.
func (s *Store) RecentLoginFailures(ctx context.Context, username, ip string, since time.Time) (LoginFailureStats, error) {
	var stats LoginFailureStats
	var userLast, ipLast *time.Time
	if err := s.db.QueryRow(ctx, `
SELECT
	count(*) FILTER (WHERE username = $1),
	max(created_at) FILTER (WHERE username = $1),
	count(*) FILTER (WHERE ip = $2),
	max(created_at) FILTER (WHERE ip = $2)
FROM login_attempts
WHERE created_at > $3 AND (username = $1 OR ip = $2)`, username, ip, since).Scan(
		&stats.UserFailures, &userLast, &stats.IPFailures, &ipLast); err != nil {
		return LoginFailureStats{}, fmt.Errorf("recent login failures: %w", err)
	}
	if userLast != nil {
		stats.UserLast = *userLast
	}
	if ipLast != nil {
		stats.IPLast = *ipLast
	}
	return stats, nil
}

// ClearLoginFailures removes a username's recorded failures after a successful
// login, resetting its throttle counter.
func (s *Store) ClearLoginFailures(ctx context.Context, username string) error {
	if _, err := s.db.Exec(ctx, "DELETE FROM login_attempts WHERE username = $1", username); err != nil {
		return fmt.Errorf("clear login failures: %w", err)
	}
	return nil
}
