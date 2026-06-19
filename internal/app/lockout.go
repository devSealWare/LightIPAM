package app

import (
	"time"

	"github.com/devSealWare/LightIPAM/internal/store"
)

// lockoutPolicy is the login-throttling configuration evaluated on each attempt.
type lockoutPolicy struct {
	MaxAttempts int
	Window      time.Duration
	Cooldown    time.Duration
}

// lockoutDecision is the result of evaluating recent failures against a policy.
type lockoutDecision struct {
	Locked     bool
	RetryAfter time.Duration
}

// evaluateLockout decides whether a login should be blocked given recent failed
// attempts for the attempted username and the client IP. It is pure so the
// throttle logic is unit-tested without a database. A login is locked when
// either key has reached MaxAttempts failures (already filtered to the window by
// the caller) and the most recent of those failures is still within the
// cooldown; the more restrictive of the two keys wins. Once the cooldown elapses
// the lock clears, even before the counted failures age out of the window.
func evaluateLockout(policy lockoutPolicy, stats store.LoginFailureStats, now time.Time) lockoutDecision {
	user := lockoutForKey(policy, stats.UserFailures, stats.UserLast, now)
	ip := lockoutForKey(policy, stats.IPFailures, stats.IPLast, now)
	if ip.RetryAfter > user.RetryAfter {
		return ip
	}
	return user
}

func lockoutForKey(policy lockoutPolicy, failures int, lastFailure time.Time, now time.Time) lockoutDecision {
	if policy.MaxAttempts <= 0 || failures < policy.MaxAttempts || lastFailure.IsZero() {
		return lockoutDecision{}
	}
	unlockAt := lastFailure.Add(policy.Cooldown)
	if !now.Before(unlockAt) {
		return lockoutDecision{}
	}
	return lockoutDecision{Locked: true, RetryAfter: unlockAt.Sub(now)}
}
