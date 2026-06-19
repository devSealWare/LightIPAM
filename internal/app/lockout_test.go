package app

import (
	"testing"
	"time"

	"github.com/devSealWare/LightIPAM/internal/store"
)

func TestEvaluateLockout(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	standard := lockoutPolicy{MaxAttempts: 5, Window: 15 * time.Minute, Cooldown: 15 * time.Minute}

	tests := []struct {
		name       string
		policy     lockoutPolicy
		stats      store.LoginFailureStats
		wantLocked bool
		wantRetry  time.Duration
	}{
		{
			name:   "below threshold is open",
			policy: standard,
			stats:  store.LoginFailureStats{UserFailures: 4, UserLast: now.Add(-1 * time.Minute)},
		},
		{
			name:       "username at threshold locks for cooldown",
			policy:     standard,
			stats:      store.LoginFailureStats{UserFailures: 5, UserLast: now.Add(-1 * time.Minute)},
			wantLocked: true,
			wantRetry:  14 * time.Minute,
		},
		{
			name:       "ip at threshold locks even when username clean",
			policy:     standard,
			stats:      store.LoginFailureStats{IPFailures: 6, IPLast: now.Add(-5 * time.Minute)},
			wantLocked: true,
			wantRetry:  10 * time.Minute,
		},
		{
			name:   "cooldown elapsed clears the lock",
			policy: standard,
			stats:  store.LoginFailureStats{UserFailures: 9, UserLast: now.Add(-20 * time.Minute)},
		},
		{
			name:   "most restrictive key wins",
			policy: standard,
			stats: store.LoginFailureStats{
				UserFailures: 5, UserLast: now.Add(-10 * time.Minute),
				IPFailures: 5, IPLast: now.Add(-2 * time.Minute),
			},
			wantLocked: true,
			wantRetry:  13 * time.Minute,
		},
		{
			name:   "zero max attempts disables throttling",
			policy: lockoutPolicy{MaxAttempts: 0, Cooldown: 15 * time.Minute},
			stats:  store.LoginFailureStats{UserFailures: 50, UserLast: now},
		},
		{
			name:   "threshold count with zero timestamp does not lock",
			policy: standard,
			stats:  store.LoginFailureStats{UserFailures: 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateLockout(tt.policy, tt.stats, now)
			if got.Locked != tt.wantLocked {
				t.Fatalf("locked = %v, want %v", got.Locked, tt.wantLocked)
			}
			if got.RetryAfter != tt.wantRetry {
				t.Fatalf("retryAfter = %v, want %v", got.RetryAfter, tt.wantRetry)
			}
		})
	}
}
