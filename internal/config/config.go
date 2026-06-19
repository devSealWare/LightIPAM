package config

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port         string
	DatabaseURL  string
	AppSecret    []byte
	CookieSecure bool

	// Session lifetime. SessionAbsoluteTimeout caps how long a session can live
	// from creation regardless of activity; SessionIdleTimeout expires a session
	// that has gone untouched for that long. Both are enforced server-side.
	SessionAbsoluteTimeout time.Duration
	SessionIdleTimeout     time.Duration

	// Login throttling. After LoginMaxAttempts failures (counted per username and
	// per client IP) within LoginWindow, further attempts are locked for
	// LoginLockout. Tuned together; keep LoginWindow >= LoginLockout so the lock
	// is fully enforced before the counted failures age out.
	LoginMaxAttempts int
	LoginWindow      time.Duration
	LoginLockout     time.Duration

	// Scanner dispatch (app acts as the mTLS client to scanner agents). When
	// the client certificate files are absent, dispatch is disabled and scan
	// jobs fail cleanly instead of contacting an agent.
	ScannerClientCert string
	ScannerClientKey  string
	ScannerCACert     string
	ScanSchedulerTick time.Duration

	// ScannerAgentEndpoint, when set, is the bundled agent the app auto-enrolls
	// (as a pending agent) on boot by pulling its /register endpoint over mTLS.
	ScannerAgentEndpoint string
}

func Load() Config {
	secret := os.Getenv("APP_SECRET")
	if secret == "" {
		generated := make([]byte, 32)
		if _, err := rand.Read(generated); err != nil {
			panic(err)
		}
		secret = base64.RawURLEncoding.EncodeToString(generated)
		slog.Warn("APP_SECRET is not set; generated a temporary development secret")
	}

	return Config{
		Port:                   getenv("PORT", "8080"),
		DatabaseURL:            getenv("DATABASE_URL", "postgres://lightipam:lightipam@localhost:5432/lightipam?sslmode=disable"),
		AppSecret:              []byte(secret),
		CookieSecure:           getenv("COOKIE_SECURE", "false") == "true",
		SessionAbsoluteTimeout: durationEnv("SESSION_ABSOLUTE_TIMEOUT", 12*time.Hour),
		SessionIdleTimeout:     durationEnv("SESSION_IDLE_TIMEOUT", 30*time.Minute),
		LoginMaxAttempts:       positiveInt(getenv("LOGIN_MAX_ATTEMPTS", "5"), 5),
		LoginWindow:            durationEnv("LOGIN_ATTEMPT_WINDOW", 15*time.Minute),
		LoginLockout:           durationEnv("LOGIN_LOCKOUT", 15*time.Minute),
		ScannerClientCert:      getenv("SCANNER_CLIENT_CERT", "/certs/app.crt"),
		ScannerClientKey:       getenv("SCANNER_CLIENT_KEY", "/certs/app.key"),
		ScannerCACert:          getenv("SCANNER_CLIENT_CA", "/certs/ca.crt"),
		ScanSchedulerTick:      schedulerTick(getenv("SCAN_SCHEDULER_TICK_SECONDS", "30")),
		ScannerAgentEndpoint:   os.Getenv("SCANNER_AGENT_ENDPOINT"),
	}
}

func schedulerTick(value string) time.Duration {
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		seconds = 30
	}
	return time.Duration(seconds) * time.Second
}

// durationEnv reads a Go duration string (e.g. "12h", "30m", "90s") from the
// environment, falling back to a default when unset or unparseable. A
// non-positive value also falls back, so a misconfiguration cannot disable the
// guard it controls.
func durationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func positiveInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
