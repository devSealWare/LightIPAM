package app

import (
	"net/url"
	"testing"
	"time"
)

func TestParseSecuritySettingsForm(t *testing.T) {
	base := func() url.Values {
		return url.Values{
			"login_max_attempts":     {"5"},
			"login_window_minutes":   {"15"},
			"login_lockout_minutes":  {"10"},
			"session_idle_minutes":   {"30"},
			"session_absolute_hours": {"12"},
		}
	}

	tests := []struct {
		name    string
		mutate  func(url.Values)
		wantErr bool
		check   func(t *testing.T, s SecuritySettings)
	}{
		{
			name: "valid defaults",
			check: func(t *testing.T, s SecuritySettings) {
				if s.LoginMaxAttempts != 5 {
					t.Fatalf("max attempts = %d, want 5", s.LoginMaxAttempts)
				}
				if s.LoginWindow != 15*time.Minute {
					t.Fatalf("window = %v, want 15m", s.LoginWindow)
				}
				if s.LoginLockout != 10*time.Minute {
					t.Fatalf("lockout = %v, want 10m", s.LoginLockout)
				}
				if s.SessionIdleTimeout != 30*time.Minute {
					t.Fatalf("idle = %v, want 30m", s.SessionIdleTimeout)
				}
				if s.SessionAbsoluteTimeout != 12*time.Hour {
					t.Fatalf("absolute = %v, want 12h", s.SessionAbsoluteTimeout)
				}
				if s.LogoutEverywhereKeepsCurrent {
					t.Fatal("keep-current should default off when checkbox absent")
				}
			},
		},
		{
			name:   "keep current checkbox on",
			mutate: func(v url.Values) { v.Set("logout_keeps_current", "on") },
			check: func(t *testing.T, s SecuritySettings) {
				if !s.LogoutEverywhereKeepsCurrent {
					t.Fatal("want keep-current true")
				}
			},
		},
		{name: "max attempts zero", mutate: func(v url.Values) { v.Set("login_max_attempts", "0") }, wantErr: true},
		{name: "max attempts too high", mutate: func(v url.Values) { v.Set("login_max_attempts", "101") }, wantErr: true},
		{name: "max attempts non-numeric", mutate: func(v url.Values) { v.Set("login_max_attempts", "five") }, wantErr: true},
		{name: "window zero", mutate: func(v url.Values) { v.Set("login_window_minutes", "0") }, wantErr: true},
		{name: "idle too high", mutate: func(v url.Values) { v.Set("session_idle_minutes", "20000") }, wantErr: true},
		{name: "absolute zero", mutate: func(v url.Values) { v.Set("session_absolute_hours", "0") }, wantErr: true},
		{name: "lockout longer than window", mutate: func(v url.Values) { v.Set("login_lockout_minutes", "20") }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := base()
			if tt.mutate != nil {
				tt.mutate(form)
			}
			got, err := parseSecuritySettingsForm(form)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// TestSecuritySettingsRoundTrip guards that formValues -> parse is stable, so the
// security tab re-renders exactly what it persisted.
func TestSecuritySettingsRoundTrip(t *testing.T) {
	original := SecuritySettings{
		LoginMaxAttempts:             7,
		LoginWindow:                  20 * time.Minute,
		LoginLockout:                 20 * time.Minute,
		SessionIdleTimeout:           45 * time.Minute,
		SessionAbsoluteTimeout:       8 * time.Hour,
		LogoutEverywhereKeepsCurrent: true,
	}
	form := url.Values{}
	for k, v := range original.formValues() {
		form.Set(k, v)
	}
	got, err := parseSecuritySettingsForm(form)
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if got != original {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, original)
	}
}
